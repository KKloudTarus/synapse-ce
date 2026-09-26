package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// gitlabCIRules are the GitLab pipeline checks. A .gitlab-ci.yml is the deployment path: it holds the
// credentials that reach production and it decides what code runs with them, so what it leaves unpinned is
// what someone else gets to choose.
func gitlabCIRules() []rule.Rule {
	return []rule.Rule{
		{
			Key: "gitlab-ci-include-project-unpinned", Name: "Pipeline includes another project with no ref", Language: "GitLab CI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"gitlab-ci", "supply-chain"},
			CWE: []string{"CWE-1357"}, OWASP: []string{"A08:2021"}, Detection: rule.DetectionPattern,
			Description: "An `include` names another project but no `ref`, so it resolves to that project's default branch at pipeline time.",
			Rationale: "Without a ref the include is late-bound: whoever can push to the template project's default branch runs commands in this " +
				"pipeline, with this project's deploy credentials, and no change lands in this repository for anyone to review. A shared template " +
				"project is usually writable by more people than the services that depend on it.\n\nSource: https://docs.gitlab.com/ee/ci/yaml/#includeproject",
			Remediation:         "Pin `ref` to a tag or a commit SHA.",
			CompliantExample:    "include:\n  - project: \"devops/pipeline-templates\"\n    ref: \"v1.4.0\"\n    file: \"/docker.gitlab-ci.yml\"\n\nbuild:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			NoncompliantExample: "include:\n  - project: \"devops/pipeline-templates\"\n    file: \"/docker.gitlab-ci.yml\"\n\nbuild:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			RemediationEffort:   15,
		},
		{
			Key: "gitlab-ci-include-remote", Name: "Pipeline includes remote configuration", Language: "GitLab CI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"gitlab-ci", "supply-chain"},
			CWE: []string{"CWE-829"}, OWASP: []string{"A08:2021"}, Detection: rule.DetectionPattern,
			Description: "An `include` fetches pipeline configuration from a URL.",
			Rationale: "Whatever the URL serves when the pipeline runs becomes pipeline code holding this project's credentials. There is no " +
				"checksum, no version, and nothing in the repository that records what ran or that it changed between two builds." +
				"\n\nSource: https://docs.gitlab.com/ee/ci/yaml/#includeremote",
			Remediation:         "Vendor the file into this repository, or include it from a project on this instance with a pinned `ref`.",
			CompliantExample:    "include:\n  - local: \"/ci/docker.gitlab-ci.yml\"\n\nbuild:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			NoncompliantExample: "include:\n  - remote: \"https://example.com/ci/docker.gitlab-ci.yml\"\n\nbuild:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			RemediationEffort:   30,
		},
		{
			Key: "gitlab-ci-debug-trace-enabled", Name: "Pipeline enables debug tracing", Language: "GitLab CI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"gitlab-ci", "secrets"},
			CWE: []string{"CWE-532"}, OWASP: []string{"A09:2021"}, Detection: rule.DetectionPattern,
			Description: "`CI_DEBUG_TRACE` is enabled.",
			Rationale: "Debug tracing makes the runner trace every command, which writes the value of every variable into the job log, masked " +
				"project and group variables included. Anyone who can read a job log then reads the deploy credentials, and the log outlives the job." +
				"\n\nSource: https://docs.gitlab.com/ee/ci/variables/#enable-debug-logging",
			Remediation:         "Remove the variable, and rotate any credential a job has already written to a log.",
			CompliantExample:    "variables:\n  CI_DEBUG_TRACE: \"false\"\n\nbuild:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			NoncompliantExample: "variables:\n  CI_DEBUG_TRACE: \"true\"\n\nbuild:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			RemediationEffort:   5,
		},
		{
			Key: "gitlab-ci-script-injection", Name: "Untrusted pipeline variable is evaluated as code", Language: "GitLab CI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityHigh, Tags: []string{"gitlab-ci", "injection"},
			CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021"}, Detection: rule.DetectionPattern,
			Description: "A job evaluates a variable whose value comes from outside the project through `eval` or a shell `-c` string.",
			Rationale: "A commit message, a branch name and a merge-request title are chosen by whoever opens the merge request. GitLab passes them " +
				"as environment variables, and shell parameter expansion does not re-parse a value as code, so an ordinary \"$CI_COMMIT_MESSAGE\" is " +
				"data. `eval` and a `-c` string parse it a second time, and that is where the text becomes a command holding the job's credentials. " +
				"A command substitution expands the variable inside a string that was already parsed, so it is data there and is not reported." +
				"\n\nSource: https://docs.gitlab.com/ee/ci/variables/predefined_variables.html",
			Remediation:         "Read the value into a quoted variable and pass it as data; never through `eval` or a shell `-c` string.",
			CompliantExample:    "build:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - printf '%s' \"$CI_COMMIT_MESSAGE\" > message.txt\n    - node ./scripts/changelog.js message.txt\n",
			NoncompliantExample: "build:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - eval \"echo $CI_COMMIT_MESSAGE\"\n",
			RemediationEffort:   30,
		},
		{
			Key: "gitlab-ci-registry-password-on-command-line", Name: "Registry credential passed on the command line", Language: "GitLab CI",
			Type: rule.TypeSecurityHotspot, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"gitlab-ci", "secrets"},
			CWE: []string{"CWE-214"}, OWASP: []string{"A09:2021"}, Detection: rule.DetectionPattern,
			Description: "A registry login passes the password as an argument instead of on standard input.",
			Rationale: "An argument is readable in the node's process table by anything else running on that runner, and it is echoed verbatim by any " +
				"shell trace, so the credential reaches places the job never intended. Docker ships `--password-stdin` for exactly this." +
				"\n\nSource: https://docs.docker.com/reference/cli/docker/login/#password-stdin",
			Remediation:         "Pipe the credential: `echo \"$CI_REGISTRY_PASSWORD\" | docker login --password-stdin -u \"$CI_REGISTRY_USER\" \"$CI_REGISTRY\"`.",
			CompliantExample:    "build:\n  image: docker@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - echo \"$CI_REGISTRY_PASSWORD\" | docker login --password-stdin -u \"$CI_REGISTRY_USER\" \"$CI_REGISTRY\"\n",
			NoncompliantExample: "build:\n  image: docker@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - docker login -u \"$CI_REGISTRY_USER\" -p \"$CI_REGISTRY_PASSWORD\" \"$CI_REGISTRY\"\n",
			RemediationEffort:   5,
		},
		{
			Key: "gitlab-ci-curl-pipe-shell", Name: "Pipeline executes a downloaded script", Language: "GitLab CI",
			Type: rule.TypeVulnerability, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityMedium, Tags: []string{"gitlab-ci", "supply-chain"},
			CWE: []string{"CWE-494"}, OWASP: []string{"A08:2021"}, Detection: rule.DetectionPattern,
			Description: "A job downloads a script and pipes it straight into a shell.",
			Rationale: "Whatever the URL serves at pipeline time executes with the job's credentials, with no checksum and no record of what ran. " +
				"A pipe also hides a partial download: a truncated script still runs, up to the point the connection dropped." +
				"\n\nSource: https://cwe.mitre.org/data/definitions/494.html",
			Remediation:         "Download to a file, verify a pinned checksum, then execute it.",
			CompliantExample:    "build:\n  image: debian@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - curl -fsSL -o install.sh https://example.com/install.sh\n    - echo \"0000000000000000000000000000000000000000000000000000000000000000  install.sh\" | sha256sum -c -\n    - ./install.sh\n",
			NoncompliantExample: "build:\n  image: debian@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - curl -fsSL https://example.com/install.sh | sh\n",
			RemediationEffort:   30,
		},
		{
			Key: "gitlab-ci-image-no-digest", Name: "Job image is not pinned to a digest", Language: "GitLab CI",
			Type: rule.TypeSecurityHotspot, Qualities: []rule.Quality{rule.QualitySecurity},
			DefaultSeverity: shared.SeverityLow, Tags: []string{"gitlab-ci", "supply-chain"},
			CWE: []string{"CWE-1357"}, OWASP: []string{"A08:2021"}, Detection: rule.DetectionPattern,
			Description: "A job or service image names a tag rather than a digest.",
			Rationale: "A tag is a moving pointer, so the runner executes whatever it resolves to when the pipeline runs. A republished tag changes " +
				"the build and the credentials that build holds, and two runs of the same commit stop being the same run. A reference built from a " +
				"variable is not judged, because what it expands to is not in the file." +
				"\n\nSource: https://docs.gitlab.com/ee/ci/yaml/#image",
			Remediation:         "Pin the image by digest (`name@sha256:...`).",
			CompliantExample:    "build:\n  image: node@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  script:\n    - npm ci\n",
			NoncompliantExample: "build:\n  image: node:20\n  script:\n    - npm ci\n",
			RemediationEffort:   15,
		},
	}
}
