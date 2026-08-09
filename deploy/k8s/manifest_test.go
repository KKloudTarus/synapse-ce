// Package k8s_test guards the shipped Kubernetes manifests against defects that otherwise only surface
// when a real API server rejects them.
//
// This exists because `deploy/k8s/cluster-agent.yaml` shipped with a volumeMount naming a volume that
// was never declared. Nothing in the Go build or in `kubectl apply --dry-run=client` looks at that: the
// API server caught it, which meant the defect lived on main until a kind job spun up a cluster. These
// checks are cheap, run in the ordinary Go job, and fail with a message that names the problem.
package k8s_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

const manifestPath = "cluster-agent.yaml"

type manifestDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				Containers []struct {
					Name         string `yaml:"name"`
					VolumeMounts []struct {
						Name      string `yaml:"name"`
						MountPath string `yaml:"mountPath"`
					} `yaml:"volumeMounts"`
				} `yaml:"containers"`
				Volumes []struct {
					Name   string `yaml:"name"`
					Secret *struct {
						SecretName  string `yaml:"secretName"`
						Optional    *bool  `yaml:"optional"`
						DefaultMode *int   `yaml:"defaultMode"`
					} `yaml:"secret"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func loadDeployment(t *testing.T) manifestDoc {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read %s: %v", manifestPath, err)
	}
	dec := yaml.NewDecoder(bytesReader(raw))
	for {
		var doc manifestDoc
		err := dec.Decode(&doc)
		if err != nil {
			break
		}
		if doc.Kind == "Deployment" {
			return doc
		}
	}
	t.Fatalf("%s contains no Deployment", manifestPath)
	return manifestDoc{}
}

// TestEveryVolumeMountResolves is the check that was missing. A mount naming an undeclared volume makes
// the API server refuse the whole Deployment ("volumeMounts[1].name: Not found"), so the agent is not
// merely misconfigured — it never exists.
func TestEveryVolumeMountResolves(t *testing.T) {
	dep := loadDeployment(t)
	spec := dep.Spec.Template.Spec

	declared := make(map[string]bool, len(spec.Volumes))
	for _, v := range spec.Volumes {
		declared[v.Name] = true
	}
	if len(spec.Containers) == 0 {
		t.Fatal("the Deployment declares no containers")
	}
	for _, c := range spec.Containers {
		if len(c.VolumeMounts) == 0 {
			continue
		}
		for _, m := range c.VolumeMounts {
			if !declared[m.Name] {
				t.Errorf("container %q mounts volume %q at %s, but no such volume is declared (the API server will reject this Deployment)",
					c.Name, m.Name, m.MountPath)
			}
		}
	}
}

// TestEnrolTokenSecretStaysOptional pins a property that reads like a loose end and is not one.
//
// The enrolment token is consumed once; afterwards the agent holds a long-lived credential on its state
// volume and the Secret is dead weight, so deleting it is correct hygiene. If the mount were required,
// that correct cleanup would leave a pod that can never restart. Anyone "tightening" this to
// optional: false should have to delete this test and read why first.
func TestEnrolTokenSecretStaysOptional(t *testing.T) {
	spec := loadDeployment(t).Spec.Template.Spec
	for _, v := range spec.Volumes {
		if v.Secret == nil {
			continue
		}
		if v.Secret.Optional == nil || !*v.Secret.Optional {
			t.Errorf("secret volume %q (%s) is not optional: the pod could not restart after the spent one-time token is deleted",
				v.Name, v.Secret.SecretName)
		}
		// Files in a Secret volume are owned root:fsGroup, so an owner-only mode locks out the
		// container's own non-root user. 0440 is readable through fsGroup and by nobody else.
		if v.Secret.DefaultMode == nil {
			t.Errorf("secret volume %q sets no defaultMode; a token would default to world-readable 0644", v.Name)
			continue
		}
		if mode := *v.Secret.DefaultMode; mode&0o007 != 0 {
			t.Errorf("secret volume %q has mode %#o, which grants access to other: a bearer token must not be world-readable", v.Name, mode)
		}
	}
}
