package tests

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProductionChartSecurityAndDataGovernance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell chart tests are covered by Helm CI on Linux")
	}
	chartDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"render_test.sh", "data_governance_test.sh"} {
		t.Run(script, func(t *testing.T) {
			cmd := exec.Command("sh", filepath.Join(chartDir, "testdata", script))
			cmd.Dir = chartDir
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("chart test %s failed: %v\n%s", script, err, output)
			}
		})
	}
}

func TestRenderedRolesKeepExecutionAndCredentialsSeparate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Helm chart rendering is covered on Linux")
	}
	chartDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	type environment struct {
		Name, Value string
		ValueFrom   struct {
			SecretKeyRef struct{ Name, Key string } `yaml:"secretKeyRef"`
		} `yaml:"valueFrom"`
	}
	type workload struct {
		Kind string
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name string
						Env  []environment
					}
				}
			}
		}
	}
	for _, mode := range []string{"controlPlaneOnly", "externalNative", "inClusterBroker"} {
		t.Run(mode, func(t *testing.T) {
			values := filepath.Join(chartDir, "tests", "production-values.yaml")
			if mode == "controlPlaneOnly" {
				values = filepath.Join(chartDir, "values-dev.yaml")
			}
			args := []string{"template", "synapse", chartDir, "-f", values, "--kube-version", "1.29.0", "--set", "execution.mode=" + mode}
			if mode == "inClusterBroker" {
				args = append(args, "--set", "egressBroker.enabled=true",
					"--set", "egressBroker.grantAuthorityURL=https://grant.internal.example",
					"--set", "egressBroker.grantPublicKey=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzJieXRlcw==",
					"--set", "egressBroker.privileged=true")
			}
			cmd := exec.Command("helm", args...)
			output, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			decoder := yaml.NewDecoder(bytes.NewReader(output))
			for {
				var document workload
				if err := decoder.Decode(&document); err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				if document.Kind != "Deployment" && document.Kind != "Job" {
					continue
				}
				for _, container := range document.Spec.Template.Spec.Containers {
					if container.Name != "api" && container.Name != "worker" && container.Name != "migrate" {
						continue
					}
					seen[container.Name] = true
					env := make(map[string]environment)
					for _, item := range container.Env {
						if _, duplicate := env[item.Name]; duplicate &&
							(item.Name == "SYNAPSE_API_TOKEN" || item.Name == "SYNAPSE_DB_MIGRATION_DSN" || item.Name == "SYNAPSE_TOOL_EXECUTION_MODE") {
							t.Fatalf("%s has duplicate authority/role variable %s", container.Name, item.Name)
						}
						env[item.Name] = item
					}
					_, humanToken := env["SYNAPSE_API_TOKEN"]
					_, migrationCredential := env["SYNAPSE_DB_MIGRATION_DSN"]
					if humanToken != (container.Name == "api") || migrationCredential != (container.Name == "migrate") {
						t.Fatalf("%s received wrong authority: human=%v migration=%v", container.Name, humanToken, migrationCredential)
					}
					if container.Name == "worker" && env["SYNAPSE_TOOL_EXECUTION_MODE"].Value != "worker" {
						t.Fatal("worker cannot start with the rendered execution role")
					}
					if container.Name == "api" && mode != "controlPlaneOnly" && env["SYNAPSE_TOOL_EXECUTION_MODE"].Value != "dispatch-only" {
						t.Fatal("production API must not execute worker tools")
					}
					if container.Name == "migrate" {
						runtimeRef := env["SYNAPSE_DB_DSN"].ValueFrom.SecretKeyRef
						migrationRef := env["SYNAPSE_DB_MIGRATION_DSN"].ValueFrom.SecretKeyRef
						if runtimeRef.Name == "" || runtimeRef.Key == "" || migrationRef.Name == "" || migrationRef.Key == "" || runtimeRef == migrationRef {
							t.Fatal("migration requires separately referenced runtime and migration credentials")
						}
					}
				}
			}
			if !seen["api"] || !seen["migrate"] || seen["worker"] != (mode == "inClusterBroker") {
				t.Fatalf("unexpected rendered execution topology: %v", seen)
			}
		})
	}
}
