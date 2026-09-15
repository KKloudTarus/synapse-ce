package scabench

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var ErrTargetNativeComparisonUnavailable = errors.New("target-native package comparison is unavailable")

// RPMEVR preserves exact RPM epoch, version, and release components. An absent
// epoch is represented as zero before it reaches the target-native rpm tool.
type RPMEVR struct {
	Epoch   *int
	Version string
	Release string
}

func (evr RPMEVR) Canonical() (string, error) {
	if strings.TrimSpace(evr.Version) == "" || strings.TrimSpace(evr.Release) == "" || containsNativeControl(evr.Version) || containsNativeControl(evr.Release) {
		return "", fmt.Errorf("RPM EVR requires exact version and release")
	}
	epoch := 0
	if evr.Epoch != nil {
		epoch = *evr.Epoch
	}
	if epoch < 0 {
		return "", fmt.Errorf("RPM epoch cannot be negative")
	}
	return strconv.Itoa(epoch) + ":" + evr.Version + "-" + evr.Release, nil
}

func canonicalRPMEVR(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || containsNativeControl(value) || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("RPM EVR must be an exact non-whitespace value")
	}
	if strings.Count(value, ":") > 1 || strings.Count(value, "-") > 1 {
		return "", fmt.Errorf("RPM EVR has an invalid epoch, version, or release")
	}

	epoch := uint64(0)
	versionRelease := value
	if rawEpoch, remainder, present := strings.Cut(value, ":"); present {
		if rawEpoch == "" || remainder == "" {
			return "", fmt.Errorf("RPM EVR has an invalid epoch")
		}
		parsed, err := strconv.ParseUint(rawEpoch, 10, 64)
		if err != nil {
			return "", fmt.Errorf("RPM EVR has an invalid epoch")
		}
		epoch = parsed
		versionRelease = remainder
	}

	version := versionRelease
	release := ""
	if parsedVersion, parsedRelease, present := strings.Cut(versionRelease, "-"); present {
		if parsedVersion == "" || parsedRelease == "" {
			return "", fmt.Errorf("RPM EVR has an invalid version or release")
		}
		version = parsedVersion
		release = "-" + parsedRelease
	}
	if version == "" || strings.ContainsAny(version, ":-") {
		return "", fmt.Errorf("RPM EVR has an invalid version")
	}
	return strconv.FormatUint(epoch, 10) + ":" + version + release, nil
}

func validateNativeVersionRequest(request ports.NativeVersionComparisonRequest) error {
	if !validNativeDigest(request.TargetDigest) {
		return fmt.Errorf("target digest is invalid")
	}
	if request.Family != ports.NativePackageDeb && request.Family != ports.NativePackageRPM {
		return fmt.Errorf("package family %q is invalid", request.Family)
	}
	if strings.TrimSpace(request.LeftEVR) == "" || strings.TrimSpace(request.RightEVR) == "" || containsNativeControl(request.LeftEVR) || containsNativeControl(request.RightEVR) {
		return fmt.Errorf("native comparison requires exact non-control EVRs")
	}
	return nil
}

func validNativeDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func containsNativeControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
