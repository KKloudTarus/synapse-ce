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

func TestParseBuildGradleDepsExcludesBuildscriptAndComments(t *testing.T) {
	src := `
buildscript {
    dependencies {
        classpath 'com.android.tools.build:gradle:8.1.0'          // build-time plugin -> must NOT be emitted
    }
}
dependencies {
    implementation 'real:lib:1.2.3'   // was 'com.fasterxml.jackson.core:jackson-databind:2.9.9' -> comment ignored
    implementation 'dyn:sel:1.+'      // dynamic selector -> must NOT be emitted (phantom-major FP)
    /* implementation 'blocked:out:9.9.9' */
    implementation 'ok:concrete:2.0.0'
}
`
	comps := ParseBuildGradleDeps([]byte(src))
	got := map[string]bool{}
	for _, c := range comps {
		got[c.Name] = true
	}
	for _, want := range []string{"real:lib", "ok:concrete"} {
		if !got[want] {
			t.Errorf("expected %s to be emitted; got %v", want, got)
		}
	}
	for _, bad := range []string{
		"com.android.tools.build:gradle",              // buildscript classpath
		"com.fasterxml.jackson.core:jackson-databind", // trailing-comment coord
		"blocked:out", // block-comment coord
		"dyn:sel",     // dynamic version 1.+
	} {
		if got[bad] {
			t.Errorf("%s must NOT be emitted", bad)
		}
	}
	if len(comps) != 2 {
		t.Errorf("want exactly 2 components (real:lib, ok:concrete), got %d: %+v", len(comps), comps)
	}
}

func TestSplitGradleCoord(t *testing.T) {
	cases := []struct {
		in                       string
		wantOK                   bool
		group, artifact, version string
	}{
		{"g:a:1.2.3", true, "g", "a", "1.2.3"},
		{"g:a:1.0@aar", true, "g", "a", "1.0"},    // @ext stripped
		{"g:a:1.0:jar", true, "g", "a", "1.0"},    // classifier ignored (version is 3rd part)
		{"g:a", false, "", "", ""},                // version-less (BOM)
		{"g:a:${v}", false, "", "", ""},           // interpolated
		{"g:a:1.+", false, "", "", ""},            // dynamic
		{"g:a:latest.release", false, "", "", ""}, // word
	}
	for _, c := range cases {
		g, a, v, ok := splitGradleCoord(c.in)
		if ok != c.wantOK || (ok && (g != c.group || a != c.artifact || v != c.version)) {
			t.Errorf("splitGradleCoord(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)", c.in, g, a, v, ok, c.group, c.artifact, c.version, c.wantOK)
		}
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
