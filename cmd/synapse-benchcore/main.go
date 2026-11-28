// Command synapse-benchcore runs the engine-neutral benchmark core (#1640): it runs the scorer's control
// suites, converts the legacy SCA benchmark into neutral truth and observations, issues run-start
// receipts, binds scorecards and reports closure status. It executes no scanner.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchcore"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchcore/scabridge"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// Exit codes.
const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitNotClosed = 3
)

const usage = `usage: synapse-benchcore <command> [flags]

commands:
  controls            run the manifest's control suites and print their results (score runs them too)
  truth-from-scabench convert the legacy SCA oracle into a neutral truth set
  observe-scabench    convert one engine's legacy SCA observations into neutral observations
  receipt             issue a run-start receipt for a profile
  score               score one engine's observations and bind the scorecard
  verify              recompute a scorecard from its inputs; exit 1 unless it matches
  status              report closure status from scorecards; exit 3 while not closed
  digest              print the digest of a manifest or a truth set
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	commands := map[string]func([]string, io.Writer) (int, error){
		"controls":            cmdControls,
		"truth-from-scabench": cmdTruthFromSCABench,
		"observe-scabench":    cmdObserveSCABench,
		"receipt":             cmdReceipt,
		"score":               cmdScore,
		"verify":              cmdVerify,
		"status":              cmdStatus,
		"digest":              cmdDigest,
	}
	command, ok := commands[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return exitUsage
	}
	code, err := command(args[1:], stdout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "synapse-benchcore %s: %v\n", args[0], err)
		var usageErr usageError
		if errors.As(err, &usageErr) {
			return exitUsage
		}
		return exitError
	}
	return code
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func parse(name string, args []string, required ...string) (*flag.FlagSet, map[string]*string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, f := range []string{"manifest", "profile", "oracle", "catalog", "observations", "engine", "version", "receipt", "truth", "card", "run-key", "commit", "runner", "source-tree", "recorded-at", "kind", "file"} {
		values[f] = fs.String(f, "", f)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, usageError{err.Error()}
	}
	var missing []string
	for _, r := range required {
		if strings.TrimSpace(*values[r]) == "" {
			missing = append(missing, "-"+r)
		}
	}
	if len(missing) > 0 {
		return nil, nil, usageError{"missing " + strings.Join(missing, ", ")}
	}
	return fs, values, nil
}

func open[T any](path string, decode func(io.Reader) (T, error)) (T, error) {
	var zero T
	f, err := os.Open(path) // #nosec G304 -- operator-supplied benchmark input
	if err != nil {
		return zero, err
	}
	defer func() { _ = f.Close() }()
	v, err := decode(f)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func write(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdControls(args []string, out io.Writer) (int, error) {
	_, v, err := parse("controls", args, "manifest")
	if err != nil {
		return 0, err
	}
	m, err := open(*v["manifest"], benchcore.DecodeManifest)
	if err != nil {
		return 0, err
	}
	results, _, err := benchcore.RunControlSuites(m)
	if err != nil {
		return 0, err
	}
	return exitOK, write(out, results)
}

func cmdTruthFromSCABench(args []string, out io.Writer) (int, error) {
	_, v, err := parse("truth-from-scabench", args, "oracle", "catalog", "profile", "version")
	if err != nil {
		return 0, err
	}
	oracle, err := open(*v["oracle"], scabench.DecodeOracle)
	if err != nil {
		return 0, err
	}
	catalog, err := open(*v["catalog"], scabench.DecodeCatalog)
	if err != nil {
		return 0, err
	}
	truth, err := scabridge.Truth(*v["profile"], *v["version"], catalog, oracle)
	if err != nil {
		return 0, err
	}
	return exitOK, write(out, truth.Canonical())
}

// cmdObserveSCABench converts one engine's observations. Its capabilities come from the manifest's frozen
// enrollment; it reads no oracle.
func cmdObserveSCABench(args []string, out io.Writer) (int, error) {
	_, v, err := parse("observe-scabench", args, "observations", "manifest", "profile", "engine")
	if err != nil {
		return 0, err
	}
	m, err := open(*v["manifest"], benchcore.DecodeManifest)
	if err != nil {
		return 0, err
	}
	profile, ok := m.Profile(*v["profile"])
	if !ok {
		return 0, fmt.Errorf("profile %q is not in the manifest", *v["profile"])
	}
	var capabilities []string
	enrolled := false
	for _, e := range profile.RequiredEnrollment {
		if e.EngineID == *v["engine"] {
			capabilities, enrolled = e.DeclaredCapabilities, true
		}
	}
	if !enrolled {
		return 0, fmt.Errorf("engine %q is not enrolled in profile %s", *v["engine"], profile.ID)
	}
	set, err := open(*v["observations"], scabench.DecodeObservationSet)
	if err != nil {
		return 0, err
	}
	if set.CatalogDigest != profile.Corpus.Digest {
		return 0, fmt.Errorf("observation set is of catalog %s; profile %s froze %s", set.CatalogDigest, profile.ID, profile.Corpus.Digest)
	}
	neutral := []benchcore.Observation{}
	for _, o := range set.Observations {
		if string(o.Engine) != *v["engine"] {
			continue
		}
		n, err := scabridge.Observation(profile.ID, o, capabilities)
		if err != nil {
			return 0, err
		}
		neutral = append(neutral, n.Canonical())
	}
	return exitOK, write(out, neutral)
}

func cmdReceipt(args []string, out io.Writer) (int, error) {
	_, v, err := parse("receipt", args, "manifest", "profile", "run-key", "commit", "runner")
	if err != nil {
		return 0, err
	}
	m, err := open(*v["manifest"], benchcore.DecodeManifest)
	if err != nil {
		return 0, err
	}
	receipt, err := benchcore.NewRunStartReceipt(m, benchcore.RunStart{
		ProfileID: *v["profile"], RunKey: *v["run-key"], ImplementationCommit: *v["commit"],
		SourceTreeDigest: *v["source-tree"], RunnerIdentity: *v["runner"], RecordedAt: *v["recorded-at"],
	})
	if err != nil {
		return 0, err
	}
	return exitOK, write(out, receipt)
}

func bind(v map[string]*string) (benchcore.Scorecard, error) {
	m, err := open(*v["manifest"], benchcore.DecodeManifest)
	if err != nil {
		return benchcore.Scorecard{}, err
	}
	receipt, err := open(*v["receipt"], benchcore.DecodeReceipt)
	if err != nil {
		return benchcore.Scorecard{}, err
	}
	truth, err := open(*v["truth"], benchcore.DecodeTruth)
	if err != nil {
		return benchcore.Scorecard{}, err
	}
	observations, err := open(*v["observations"], benchcore.DecodeObservations)
	if err != nil {
		return benchcore.Scorecard{}, err
	}
	if len(observations) == 0 {
		return benchcore.Scorecard{}, errors.New("no observations: an engine that ran nothing has no scorecard to bind")
	}
	return benchcore.BindScorecard(m, receipt, benchcore.Binding{Engine: observations[0].Engine, Truth: truth, Observations: observations})
}

func cmdScore(args []string, out io.Writer) (int, error) {
	_, v, err := parse("score", args, "manifest", "receipt", "truth", "observations")
	if err != nil {
		return 0, err
	}
	card, err := bind(v)
	if err != nil {
		return 0, err
	}
	return exitOK, write(out, card)
}

// cmdVerify recomputes a scorecard from the inputs it names and requires the same id. status only checks
// that a card is consistent with the manifest; verify proves the core computed it from these inputs.
func cmdVerify(args []string, out io.Writer) (int, error) {
	_, v, err := parse("verify", args, "manifest", "receipt", "truth", "observations", "card")
	if err != nil {
		return 0, err
	}
	claimed, err := open(*v["card"], benchcore.DecodeScorecard)
	if err != nil {
		return 0, err
	}
	recomputed, err := bind(v)
	if err != nil {
		return 0, err
	}
	if recomputed.ID != claimed.ID {
		return 0, fmt.Errorf("scorecard %s does not match the %s recomputed from its inputs", claimed.ID, recomputed.ID)
	}
	_, err = fmt.Fprintln(out, "verified", claimed.ID)
	return exitOK, err
}

type statusReport struct {
	Manifest string            `json:"manifest"`
	Revision int               `json:"revision"`
	Profiles map[string]string `json:"profiles"`
	Closed   bool              `json:"closed"`
}

func cmdStatus(args []string, out io.Writer) (int, error) {
	fs, v, err := parse("status", args, "manifest")
	if err != nil {
		return 0, err
	}
	m, err := open(*v["manifest"], benchcore.DecodeManifest)
	if err != nil {
		return 0, err
	}
	var cards []benchcore.Scorecard
	for _, path := range fs.Args() {
		card, err := open(path, benchcore.DecodeScorecard)
		if err != nil {
			return 0, err
		}
		cards = append(cards, card)
	}
	status := benchcore.ClosureStatus(m, cards)
	report := statusReport{Manifest: m.ManifestID, Revision: m.Revision, Profiles: status, Closed: benchcore.Closed(status)}
	if err := write(out, report); err != nil {
		return 0, err
	}
	if !report.Closed {
		return exitNotClosed, nil
	}
	return exitOK, nil
}

func cmdDigest(args []string, out io.Writer) (int, error) {
	_, v, err := parse("digest", args, "kind", "file")
	if err != nil {
		return 0, err
	}
	var digest string
	switch *v["kind"] {
	case "manifest":
		m, err := open(*v["file"], benchcore.DecodeManifest)
		if err != nil {
			return 0, err
		}
		digest, err = benchcore.DigestManifest(m)
		if err != nil {
			return 0, err
		}
	case "truth":
		t, err := open(*v["file"], benchcore.DecodeTruth)
		if err != nil {
			return 0, err
		}
		digest, err = benchcore.DigestTruth(t)
		if err != nil {
			return 0, err
		}
	default:
		return 0, usageError{"-kind must be manifest or truth"}
	}
	_, err = fmt.Fprintln(out, digest)
	return exitOK, err
}
