package dotnetreach

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
)

// assemblyWithNamespaces builds a synthetic .NET assembly (PE + metadata) that defines one type in each of
// the given namespaces, so ExportedNamespaces returns exactly those namespaces.
func assemblyWithNamespaces(t *testing.T, namespaces ...string) []byte {
	t.Helper()
	items := append([]string{"T"}, namespaces...)
	heap, off := stringsHeap(items...)
	moduleRow := make([]byte, 2+2+3*2)
	rowBytes := append([]byte{}, moduleRow...)
	for _, ns := range namespaces {
		row := make([]byte, 14)
		binary.LittleEndian.PutUint16(row[4:], uint16(off["T"]))
		binary.LittleEndian.PutUint16(row[6:], uint16(off[ns]))
		rowBytes = append(rowBytes, row...)
	}
	tables := buildTablesStream(uint64(1)<<0x00|uint64(1)<<0x02,
		map[int]uint32{0x00: 1, 0x02: uint32(len(namespaces))}, rowBytes)
	return buildPE(assembleMetadata(tables, heap))
}

// TestLoadReachabilityDataReadsRealNamespaces proves the core fix: a NuGet id whose API namespace differs
// from the id (AWSSDK.S3 -> Amazon.S3) is resolved to its REAL namespace from the restored assembly, so a
// package used via `using Amazon.S3` is never falsely reported unreferenced.
func TestLoadReachabilityDataReadsRealNamespaces(t *testing.T) {
	proj := t.TempDir()
	cache := t.TempDir()
	mustWriteBytes(t, filepath.Join(cache, "awssdk.s3", "3.7.0", "lib", "netstandard2.0", "AWSSDK.S3.dll"),
		assemblyWithNamespaces(t, "Amazon.S3", "Amazon.S3.Model"))
	assets := `{"version":3,
	  "targets":{"net8.0":{"AWSSDK.S3/3.7.0":{"type":"package","compile":{"lib/netstandard2.0/AWSSDK.S3.dll":{}}}}},
	  "libraries":{"AWSSDK.S3/3.7.0":{"type":"package","path":"awssdk.s3/3.7.0","files":["lib/netstandard2.0/AWSSDK.S3.dll"]}},
	  "packageFolders":{"` + filepath.ToSlash(cache) + `":{}}}`
	mustWrite(t, filepath.Join(proj, "obj", "project.assets.json"), assets)

	got, present, err := Loader{}.LoadReachabilityData(context.Background(), proj, []string{"AWSSDK.S3"})
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("a restore graph is present")
	}
	pn, ok := got["awssdk.s3"]
	if !ok || !pn.Complete {
		t.Fatalf("awssdk.s3: want complete namespaces, got %+v", pn)
	}
	found := map[string]bool{}
	for _, ns := range pn.Namespaces {
		found[ns] = true
	}
	if !found["amazon.s3"] || !found["amazon.s3.model"] {
		t.Errorf("want real namespaces amazon.s3(.model); got %v", pn.Namespaces)
	}
}

func TestLoadReachabilityDataAbsentWhenNoRestoreGraph(t *testing.T) {
	proj := t.TempDir()
	mustWrite(t, filepath.Join(proj, "Program.cs"), "class P {}")
	got, present, err := Loader{}.LoadReachabilityData(context.Background(), proj, []string{"Serilog"})
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("with no project.assets.json, build-aware data must be absent (caller fails closed)")
	}
	if len(got) != 0 {
		t.Errorf("no packages should resolve; got %v", got)
	}
}

func TestLoadReachabilityDataIncompleteWhenAssemblyMissing(t *testing.T) {
	proj := t.TempDir()
	cache := t.TempDir() // empty: the referenced dll does not exist on disk
	assets := `{"version":3,
	  "targets":{"net8.0":{"Serilog/3.1.1":{"type":"package","compile":{"lib/net8.0/Serilog.dll":{}}}}},
	  "libraries":{"Serilog/3.1.1":{"type":"package","path":"serilog/3.1.1","files":["lib/net8.0/Serilog.dll"]}},
	  "packageFolders":{"` + filepath.ToSlash(cache) + `":{}}}`
	mustWrite(t, filepath.Join(proj, "obj", "project.assets.json"), assets)

	got, present, err := Loader{}.LoadReachabilityData(context.Background(), proj, []string{"Serilog"})
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("a restore graph is present")
	}
	if pn := got["serilog"]; pn.Complete {
		t.Errorf("a missing assembly must make the namespace set incomplete (fail closed); got %+v", pn)
	}
}

func mustWriteBytes(t *testing.T, path string, body []byte) {
	t.Helper()
	mustWrite(t, path, string(body))
}

func TestLoadReachabilityDataDegradesOnMalformedGraph(t *testing.T) {
	proj := t.TempDir()
	cache := t.TempDir()
	mustWriteBytes(t, filepath.Join(cache, "foo", "1.0.0", "lib", "net8.0", "Foo.dll"), assemblyWithNamespaces(t, "Foo.Api"))
	good := `{"version":3,
	  "targets":{"net8.0":{"Foo/1.0.0":{"type":"package","compile":{"lib/net8.0/Foo.dll":{}}}}},
	  "libraries":{"Foo/1.0.0":{"type":"package","path":"foo/1.0.0","files":["lib/net8.0/Foo.dll"]}},
	  "packageFolders":{"` + filepath.ToSlash(cache) + `":{}}}`
	mustWrite(t, filepath.Join(proj, "a", "obj", "project.assets.json"), good)
	mustWrite(t, filepath.Join(proj, "b", "obj", "project.assets.json"), "{ this is not valid json") // malformed

	got, present, err := Loader{}.LoadReachabilityData(context.Background(), proj, []string{"Foo"})
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatal("a restore graph is present")
	}
	if pn := got["foo"]; pn.Complete {
		t.Errorf("a malformed sibling restore graph must degrade coverage (Complete=false), so no false suppression; got %+v", pn)
	}
}
