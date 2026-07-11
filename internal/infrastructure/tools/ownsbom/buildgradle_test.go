package ownsbom

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestParseBuildGradleDeps(t *testing.T) {
	src := `
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.4.3'
}
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'   // BOM-managed, no version -> skip
    implementation 'io.github.openfeign.form:feign-form:3.8.0'          // concrete -> keep
    implementation "com.amazonaws:aws-java-sdk-s3:1.12.371"             // double-quoted -> keep
    testImplementation 'org.junit.jupiter:junit-jupiter:5.8.2'          // keep
    implementation "org.example:lib:${someVersion}"                     // interpolated -> skip
    implementation('io.grpc:grpc-core:1.60.0') { exclude group: 'x' }   // keep, brace on the same line
}
repositories {
    maven { url 'https://repo.example.com/foo' }
}
`
	comps := ParseBuildGradleDeps([]byte(src))
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
		if c.PURL == "" || c.Scope != sbom.ScopeProduction {
			t.Errorf("component missing PURL/scope: %+v", c)
		}
	}
	want := map[string]string{
		"io.github.openfeign.form:feign-form": "3.8.0",
		"com.amazonaws:aws-java-sdk-s3":       "1.12.371",
		"org.junit.jupiter:junit-jupiter":     "5.8.2",
		"io.grpc:grpc-core":                   "1.60.0",
	}
	if len(comps) != len(want) {
		t.Fatalf("want %d comps, got %d: %+v", len(want), len(comps), comps)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s: want version %s, got %q", name, ver, got[name])
		}
	}
	for _, bad := range []string{"org.springframework.boot:spring-boot-starter-web", "org.example:lib"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s must not be extracted (version-less/interpolated)", bad)
		}
	}
	// A grpc-core PURL must be well-formed maven.
	if got := purlOf(comps, "io.grpc:grpc-core"); got != "pkg:maven/io.grpc/grpc-core@1.60.0" {
		t.Errorf("grpc-core PURL wrong: %q", got)
	}
}

func purlOf(comps []sbom.Component, name string) string {
	for _, c := range comps {
		if c.Name == name {
			return c.PURL
		}
	}
	return ""
}
