package sourcepackage

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	// ponytail: single-request uploads stay capped; add resumable object-store uploads before raising this ceiling.
	MaxArchiveBytes = int64(512 << 20)
	TargetPrefix    = "uploaded-source/sha256/"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Package struct {
	TenantID     shared.ID `json:"tenant_id"`
	EngagementID shared.ID `json:"engagement_id"`
	Filename     string    `json:"filename"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	Locator      string    `json:"-"`
}

func (p Package) Target() string { return TargetPrefix + p.SHA256 }

func (p Package) Validate() error {
	if p.TenantID.IsZero() || p.EngagementID.IsZero() {
		return fmt.Errorf("%w: source package tenant and engagement are required", shared.ErrValidation)
	}
	if !ValidFilename(p.Filename) {
		return fmt.Errorf("%w: uploaded source must be .zip, .tar, .tar.gz, or .tgz", shared.ErrValidation)
	}
	if p.Size <= 0 || p.Size > MaxArchiveBytes {
		return fmt.Errorf("%w: uploaded source size is invalid", shared.ErrValidation)
	}
	if !sha256Pattern.MatchString(p.SHA256) {
		return fmt.Errorf("%w: uploaded source SHA-256 is invalid", shared.ErrValidation)
	}
	if strings.TrimSpace(p.CreatedBy) == "" || p.CreatedAt.IsZero() {
		return fmt.Errorf("%w: uploaded source attribution is required", shared.ErrValidation)
	}
	return nil
}

func ValidFilename(filename string) bool {
	filename = strings.TrimSpace(strings.ReplaceAll(filename, `\`, "/"))
	if filename == "" || strings.ContainsAny(filename, "\x00\r\n") {
		return false
	}
	base := path.Base(filename)
	if base == "." || base == "/" || len(base) > 255 {
		return false
	}
	lower := strings.ToLower(base)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

func BaseFilename(filename string) string {
	return path.Base(strings.TrimSpace(strings.ReplaceAll(filename, `\`, "/")))
}

func ArchiveExtension(filename string) string {
	lower := strings.ToLower(BaseFilename(filename))
	for _, extension := range []string{".tar.gz", ".tgz", ".zip", ".tar"} {
		if strings.HasSuffix(lower, extension) {
			return extension
		}
	}
	return ""
}

func DigestFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, TargetPrefix) {
		return ""
	}
	digest := strings.TrimPrefix(target, TargetPrefix)
	if !sha256Pattern.MatchString(digest) {
		return ""
	}
	return digest
}
