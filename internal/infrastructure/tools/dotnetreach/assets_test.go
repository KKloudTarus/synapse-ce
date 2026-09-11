package dotnetreach

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAssembliesFromAssets(t *testing.T) {
	cache := t.TempDir()
	// Lay out a fake package cache: <cache>/serilog/3.1.1/lib/net8.0/Serilog.dll present; the awssdk.s3
	// runtime dll present too (its namespace is Amazon.S3, unrelated to the id, which is the whole point).
	mustWrite(t, filepath.Join(cache, "serilog", "3.1.1", "lib", "net8.0", "Serilog.dll"), "MZ")
	mustWrite(t, filepath.Join(cache, "awssdk.s3", "3.7.0", "lib", "netstandard2.0", "AWSSDK.S3.dll"), "MZ")

	assets := `{
	  "version": 3,
	  "targets": {
	    "net8.0": {
	      "Serilog/3.1.1": {"type":"package","compile":{"lib/net8.0/Serilog.dll":{}},"runtime":{"lib/net8.0/Serilog.dll":{}}},
	      "AWSSDK.S3/3.7.0": {"type":"package","compile":{"lib/netstandard2.0/AWSSDK.S3.dll":{}}},
	      "Missing.Pkg/1.0.0": {"type":"package","compile":{"lib/net8.0/Missing.Pkg.dll":{}}},
	      "Meta.Only/2.0.0": {"type":"package","compile":{"lib/net8.0/_._":{}}},
	      "Some.Project/1.0.0": {"type":"project"}
	    }
	  },
	  "libraries": {
	    "Serilog/3.1.1": {"type":"package","path":"serilog/3.1.1","files":["lib/net8.0/Serilog.dll"]},
	    "AWSSDK.S3/3.7.0": {"type":"package","path":"awssdk.s3/3.7.0","files":["lib/netstandard2.0/AWSSDK.S3.dll"]},
	    "Missing.Pkg/1.0.0": {"type":"package","path":"missing.pkg/1.0.0","files":["lib/net8.0/Missing.Pkg.dll"]},
	    "Meta.Only/2.0.0": {"type":"package","path":"meta.only/2.0.0","files":[]}
	  },
	  "packageFolders": {"` + filepath.ToSlash(cache) + `": {}}
	}`

	got, reasons, err := ResolveAssembliesFromAssets([]byte(assets))
	if err != nil {
		t.Fatal(err)
	}
	// Serilog fully resolved.
	if pa, ok := got["serilog"]; !ok || !pa.Complete || len(pa.Paths) != 1 {
		t.Fatalf("serilog: want complete with 1 path, got %+v", pa)
	}
	// AWSSDK.S3 fully resolved (real dll present).
	if pa, ok := got["awssdk.s3"]; !ok || !pa.Complete || len(pa.Paths) != 1 {
		t.Fatalf("awssdk.s3: want complete with 1 path, got %+v", pa)
	}
	// Missing.Pkg: library present but dll missing on disk -> incomplete (fail-closed).
	if pa, ok := got["missing.pkg"]; !ok || pa.Complete {
		t.Fatalf("missing.pkg: want present-but-incomplete, got %+v", pa)
	}
	// Meta.Only: only a _._ placeholder -> complete with zero paths (ships no assembly).
	if pa, ok := got["meta.only"]; !ok || !pa.Complete || len(pa.Paths) != 0 {
		t.Fatalf("meta.only: want complete with 0 paths, got %+v", pa)
	}
	// project reference is not a NuGet package.
	if _, ok := got["some.project"]; ok {
		t.Error("project reference must not be resolved as a package")
	}
	if len(reasons) == 0 {
		t.Error("a missing assembly must produce a coverage reason")
	}
}

func TestResolveAssembliesRejectsCacheEscape(t *testing.T) {
	cache := t.TempDir()
	// A file OUTSIDE the cache that a hostile library path tries to reach via "..".
	outside := filepath.Join(t.TempDir(), "evil.dll")
	mustWrite(t, outside, "MZ")
	assets := `{"version":3,
	  "targets":{"net8.0":{"Evil/1.0.0":{"type":"package","compile":{"evil.dll":{}}}}},
	  "libraries":{"Evil/1.0.0":{"type":"package","path":"../../` + filepath.Base(filepath.Dir(outside)) + `/../` + filepath.Base(filepath.Dir(outside)) + `","files":["evil.dll"]}},
	  "packageFolders":{"` + filepath.ToSlash(cache) + `":{}}}`
	got, _, err := ResolveAssembliesFromAssets([]byte(assets))
	if err != nil {
		t.Fatal(err)
	}
	if pa := got["evil"]; pa.Complete || len(pa.Paths) != 0 {
		t.Errorf("a library path escaping the cache root must not resolve; got %+v", pa)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveAssembliesUnionsMultipleVersions(t *testing.T) {
	cache := t.TempDir()
	mustWrite(t, filepath.Join(cache, "foo", "1.0.0", "lib", "net472", "Foo.dll"), "MZ")
	mustWrite(t, filepath.Join(cache, "foo", "2.0.0", "lib", "net8.0", "Foo.dll"), "MZ")
	assets := `{"version":3,
	  "targets":{
	    "net472":{"Foo/1.0.0":{"type":"package","compile":{"lib/net472/Foo.dll":{}}}},
	    "net8.0":{"Foo/2.0.0":{"type":"package","compile":{"lib/net8.0/Foo.dll":{}}}}
	  },
	  "libraries":{
	    "Foo/1.0.0":{"type":"package","path":"foo/1.0.0","files":["lib/net472/Foo.dll"]},
	    "Foo/2.0.0":{"type":"package","path":"foo/2.0.0","files":["lib/net8.0/Foo.dll"]}
	  },
	  "packageFolders":{"` + filepath.ToSlash(cache) + `":{}}}`
	got, _, err := ResolveAssembliesFromAssets([]byte(assets))
	if err != nil {
		t.Fatal(err)
	}
	pa := got["foo"]
	if len(pa.Paths) != 2 {
		t.Errorf("two versions of the same id must union their assemblies (both TFMs); got %v", pa.Paths)
	}
}

func TestResolveAssembliesIncludesRuntimeTargets(t *testing.T) {
	cache := t.TempDir()
	mustWrite(t, filepath.Join(cache, "foo", "1.0.0", "runtimes", "win", "lib", "net8.0", "Foo.dll"), "MZ")
	assets := `{"version":3,
	  "targets":{"net8.0":{"Foo/1.0.0":{"type":"package","runtimeTargets":{"runtimes/win/lib/net8.0/Foo.dll":{"assetType":"runtime","rid":"win"}}}}},
	  "libraries":{"Foo/1.0.0":{"type":"package","path":"foo/1.0.0","files":["runtimes/win/lib/net8.0/Foo.dll"]}},
	  "packageFolders":{"` + filepath.ToSlash(cache) + `":{}}}`
	got, _, err := ResolveAssembliesFromAssets([]byte(assets))
	if err != nil {
		t.Fatal(err)
	}
	if pa := got["foo"]; len(pa.Paths) != 1 || !pa.Complete {
		t.Errorf("a RID-specific runtimeTargets assembly must be resolved; got %+v", pa)
	}
}
