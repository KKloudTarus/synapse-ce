package main

import "unsafe"

func opaque(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }

func vulnerable() {}

func main() {
	var b byte
	_ = opaque(&b)
}
