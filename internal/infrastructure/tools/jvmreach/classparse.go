// Package jvmreach computes COARSE, deterministic class-level reachability for JVM projects: starting from
// the application's own compiled classes, does anything (transitively) reference a dependency's classes at
// all? A dependency whose classes are never referenced is "present but not wired in" – the signal behind
// the field complaint that a scan lists packages the project does not use. This is deliberately COARSE
// (class references, not a method call graph) and CONSERVATIVE: it only ever DEPRIORITIZES/labels a finding,
// never suppresses it, and reflection/service-loader/DI edges are invisible to it, so an "unreferenced"
// verdict means "no STATIC reference found", not "provably dead". It reads compiled bytecode only – never
// executes it – mirroring the bounded, offline archive reads the license resolvers already do.
package jvmreach

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Java.class constant-pool tags (JVMS §4.4).
const (
	tagUtf8               = 1
	tagInteger            = 3
	tagFloat              = 4
	tagLong               = 5
	tagDouble             = 6
	tagClass              = 7
	tagString             = 8
	tagFieldref           = 9
	tagMethodref          = 10
	tagInterfaceMethodref = 11
	tagNameAndType        = 12
	tagMethodHandle       = 15
	tagMethodType         = 16
	tagDynamic            = 17
	tagInvokeDynamic      = 18
	tagModule             = 19
	tagPackage            = 20
)

const classMagic = 0xCAFEBABE

var errMalformed = errors.New("malformed class file")

// parseClass reads a.class file's constant pool + this_class and returns the class's own internal name
// (e.g. "com/demo/App") and the internal names of every class it structurally references (superclass,
// interfaces, and the owner class of every method call / field access / new / cast / catch – all recorded
// as CONSTANT_Class entries). It parses ONLY up to this_class; it never reads method bodies and never
// executes anything. Bounds are checked on every read so a hostile/truncated class returns an error
// instead of panicking. Array class names ("[Lcom/foo/Bar;") are normalized to the element type.
func parseClass(data []byte) (name string, refs []string, err error) {
	c := &cursor{b: data}
	if c.u4() != classMagic {
		return "", nil, errMalformed
	}
	c.skip(4) // minor(2) + major(2)
	cpCount := int(c.u2())
	if c.err != nil || cpCount < 1 {
		return "", nil, errMalformed
	}
	utf8 := make(map[int]string, cpCount)
	classNameIdx := make(map[int]int, cpCount/4+1) // cp index of a Class entry -> its name_index
	for i := 1; i < cpCount; i++ {
		tag := c.u1()
		if c.err != nil {
			return "", nil, errMalformed
		}
		switch tag {
		case tagUtf8:
			n := int(c.u2())
			utf8[i] = c.str(n)
		case tagClass:
			classNameIdx[i] = int(c.u2())
		case tagString, tagMethodType, tagModule, tagPackage:
			c.skip(2)
		case tagInteger, tagFloat, tagFieldref, tagMethodref, tagInterfaceMethodref,
			tagNameAndType, tagDynamic, tagInvokeDynamic:
			c.skip(4)
		case tagMethodHandle:
			c.skip(3)
		case tagLong, tagDouble:
			c.skip(8)
			i++ // 8-byte constants occupy TWO pool slots (JVMS §4.4.5)
		default:
			return "", nil, errMalformed // unknown tag → don't guess sizes
		}
		if c.err != nil {
			return "", nil, errMalformed
		}
	}
	// access_flags(2) then this_class(2) → the Class entry naming this file.
	c.skip(2)
	thisIdx := int(c.u2())
	if c.err != nil {
		return "", nil, errMalformed
	}
	name = normalizeClassName(utf8[classNameIdx[thisIdx]])

	seen := make(map[string]bool, len(classNameIdx))
	refs = make([]string, 0, len(classNameIdx))
	for _, ni := range classNameIdx {
		cn := normalizeClassName(utf8[ni])
		if cn == "" || cn == name || seen[cn] {
			continue
		}
		seen[cn] = true
		refs = append(refs, cn)
	}
	return name, refs, nil
}

// normalizeClassName turns a CONSTANT_Class name into a plain internal class name: array class names
// ("[Ljava/lang/Object;" / "[[Lcom/foo/Bar;") collapse to their object element type; primitive-array
// names ("[I") and empty strings yield "". Object internal names ("com/foo/Bar") pass through.
func normalizeClassName(s string) string {
	for strings.HasPrefix(s, "[") {
		s = s[1:]
	}
	if s == "" {
		return ""
	}
	if s[0] == 'L' && strings.HasSuffix(s, ";") {
		return s[1 : len(s)-1] // array of objects: "Lcom/foo/Bar;" -> "com/foo/Bar"
	}
	if len(s) == 1 { // a primitive array element (I,J,Z,…) – not a class
		return ""
	}
	return s
}

// cursor is a bounds-checked big-endian reader over the class bytes: any out-of-range read sets err and
// makes subsequent reads no-ops, so a truncated/hostile file degrades to errMalformed, never a panic.
type cursor struct {
	b   []byte
	off int
	err error
}

func (c *cursor) u1() byte {
	if c.err != nil || c.off+1 > len(c.b) {
		c.err = errMalformed
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}

func (c *cursor) u2() uint16 {
	if c.err != nil || c.off+2 > len(c.b) {
		c.err = errMalformed
		return 0
	}
	v := binary.BigEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v
}

func (c *cursor) u4() uint32 {
	if c.err != nil || c.off+4 > len(c.b) {
		c.err = errMalformed
		return 0
	}
	v := binary.BigEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v
}

func (c *cursor) skip(n int) {
	if c.err != nil || c.off+n > len(c.b) {
		c.err = errMalformed
		return
	}
	c.off += n
}

func (c *cursor) str(n int) string {
	if c.err != nil || n < 0 || c.off+n > len(c.b) {
		c.err = errMalformed
		return ""
	}
	s := string(c.b[c.off : c.off+n])
	c.off += n
	return s
}
