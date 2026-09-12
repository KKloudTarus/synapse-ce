package jvmreach

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

const (
	accStatic = 0x0008
	accNative = 0x0100
)

type cpMember struct {
	classIndex uint16
	nameType   uint16
}

type cpNameType struct {
	name uint16
	desc uint16
}

type classModel struct {
	name       string
	super      string
	interfaces []string
	methods    map[string]*methodModel
	coord      string
	app        bool
}

type methodModel struct {
	owner  string
	name   string
	desc   string
	access uint16
	calls  []callSite
}

type callSite struct {
	opcode          byte
	owner           string
	name            string
	desc            string
	receiverTypes   []string
	receiverUnknown bool
}

type inclusionEdge struct{ from, to int }

type instruction struct {
	off     int
	op      byte
	operand int
	cpIndex uint16
}

type parsedCP struct {
	utf8      map[uint16]string
	classes   map[uint16]uint16
	members   map[uint16]cpMember
	nameTypes map[uint16]cpNameType
	invokedyn map[uint16]uint16
}

func parseTier2Class(data []byte, coord string, app bool) (*classModel, error) {
	c := &cursor{b: data}
	if c.u4() != classMagic {
		return nil, errMalformed
	}
	c.skip(4)
	cpCount := int(c.u2())
	if c.err != nil || cpCount < 1 {
		return nil, errMalformed
	}
	cp := parsedCP{
		utf8:      make(map[uint16]string, cpCount),
		classes:   make(map[uint16]uint16, cpCount/4+1),
		members:   make(map[uint16]cpMember, cpCount/4+1),
		nameTypes: make(map[uint16]cpNameType, cpCount/4+1),
		invokedyn: make(map[uint16]uint16),
	}
	for i := 1; i < cpCount; i++ {
		idx := uint16(i)
		tag := c.u1()
		switch tag {
		case tagUtf8:
			n := int(c.u2())
			cp.utf8[idx] = c.str(n)
		case tagClass:
			cp.classes[idx] = c.u2()
		case tagString, tagMethodType, tagModule, tagPackage:
			c.skip(2)
		case tagInteger, tagFloat:
			c.skip(4)
		case tagFieldref, tagMethodref, tagInterfaceMethodref:
			cp.members[idx] = cpMember{classIndex: c.u2(), nameType: c.u2()}
		case tagNameAndType:
			cp.nameTypes[idx] = cpNameType{name: c.u2(), desc: c.u2()}
		case tagDynamic:
			c.skip(4)
		case tagInvokeDynamic:
			c.skip(2)
			cp.invokedyn[idx] = c.u2()
		case tagMethodHandle:
			c.skip(3)
		case tagLong, tagDouble:
			c.skip(8)
			i++
		default:
			return nil, errMalformed
		}
		if c.err != nil {
			return nil, errMalformed
		}
	}
	access := c.u2()
	_ = access
	thisIdx := c.u2()
	superIdx := c.u2()
	m := &classModel{
		name:    cp.className(thisIdx),
		super:   cp.className(superIdx),
		methods: map[string]*methodModel{},
		coord:   coord,
		app:     app,
	}
	if m.name == "" || c.err != nil {
		return nil, errMalformed
	}
	ifaceCount := int(c.u2())
	for i := 0; i < ifaceCount; i++ {
		if n := cp.className(c.u2()); n != "" {
			m.interfaces = append(m.interfaces, n)
		}
	}
	fieldCount := int(c.u2())
	for i := 0; i < fieldCount; i++ {
		if err := skipMember(c); err != nil {
			return nil, err
		}
	}
	methodCount := int(c.u2())
	for i := 0; i < methodCount; i++ {
		mm, err := parseMethod(c, cp, m.name)
		if err != nil {
			return nil, err
		}
		if mm != nil {
			m.methods[methodSig(mm.name, mm.desc)] = mm
		}
	}
	attrs := int(c.u2())
	for i := 0; i < attrs; i++ {
		c.skip(2)
		c.skip(int(c.u4()))
	}
	if c.err != nil {
		return nil, errMalformed
	}
	return m, nil
}

func (cp parsedCP) className(idx uint16) string {
	if idx == 0 {
		return ""
	}
	return normalizeClassName(cp.utf8[cp.classes[idx]])
}

func (cp parsedCP) member(idx uint16) (owner, name, desc string, ok bool) {
	mr, ok := cp.members[idx]
	if !ok {
		return "", "", "", false
	}
	nt, ok := cp.nameTypes[mr.nameType]
	if !ok {
		return "", "", "", false
	}
	owner, name, desc = cp.className(mr.classIndex), cp.utf8[nt.name], cp.utf8[nt.desc]
	return owner, name, desc, owner != "" && name != "" && desc != ""
}

func skipMember(c *cursor) error {
	c.skip(6)
	attrs := int(c.u2())
	for i := 0; i < attrs; i++ {
		c.skip(2)
		c.skip(int(c.u4()))
	}
	if c.err != nil {
		return errMalformed
	}
	return nil
}

func parseMethod(c *cursor, cp parsedCP, owner string) (*methodModel, error) {
	access := c.u2()
	name := cp.utf8[c.u2()]
	desc := cp.utf8[c.u2()]
	attrs := int(c.u2())
	mm := &methodModel{owner: owner, name: name, desc: desc, access: access}
	for i := 0; i < attrs; i++ {
		attrName := cp.utf8[c.u2()]
		attrLen := int(c.u4())
		if c.err != nil || attrLen < 0 || c.off+attrLen > len(c.b) {
			return nil, errMalformed
		}
		start := c.off
		if attrName == "Code" {
			sub := &cursor{b: c.b[start : start+attrLen]}
			calls, err := parseCode(sub, cp, access, desc)
			if err != nil || sub.err != nil {
				if err != nil {
					return nil, err
				}
				return nil, errMalformed
			}
			mm.calls = append(mm.calls, calls...)
		}
		c.off = start + attrLen
	}
	if c.err != nil {
		return nil, errMalformed
	}
	return mm, nil
}

func parseCode(c *cursor, cp parsedCP, access uint16, desc string) ([]callSite, error) {
	c.skip(2)
	maxLocals := int(c.u2())
	codeLen := int(c.u4())
	if c.err != nil || codeLen < 0 || c.off+codeLen > len(c.b) {
		return nil, errMalformed
	}
	code := c.b[c.off : c.off+codeLen]
	c.off += codeLen
	ins, flowSafe, err := decodeInstructions(code)
	if err != nil {
		return nil, err
	}
	exCount := int(c.u2())
	if exCount > 0 {
		flowSafe = false
	}
	c.skip(exCount * 8)
	attrs := int(c.u2())
	for i := 0; i < attrs; i++ {
		c.skip(2)
		c.skip(int(c.u4()))
	}
	if c.err != nil {
		return nil, errMalformed
	}

	pts, unknown := localPointsTo(ins, cp, maxLocals, access, desc, flowSafe)
	calls := make([]callSite, 0, 8)
	for i, in := range ins {
		if in.op != 0xb6 && in.op != 0xb7 && in.op != 0xb8 && in.op != 0xb9 && in.op != 0xba {
			continue
		}
		if in.op == 0xba {
			calls = append(calls, callSite{opcode: in.op, receiverUnknown: true})
			continue
		}
		owner, name, mdesc, ok := cp.member(in.cpIndex)
		if !ok {
			continue
		}
		cs := callSite{opcode: in.op, owner: owner, name: name, desc: mdesc, receiverUnknown: true}
		if (in.op == 0xb6 || in.op == 0xb9) && flowSafe {
			if local, ok := precedingReceiverLocal(ins, i); ok && local >= 0 && local < maxLocals {
				cs.receiverTypes = sortedSet(pts[local])
				cs.receiverUnknown = unknown[local] || len(cs.receiverTypes) == 0
			}
		}
		calls = append(calls, cs)
	}
	return calls, nil
}

func methodSig(name, desc string) string { return name + "\x00" + desc }

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func localPointsTo(ins []instruction, cp parsedCP, maxLocals int, access uint16, desc string, flowSafe bool) ([]map[string]bool, []bool) {
	pts := make([]map[string]bool, maxLocals)
	unknown := make([]bool, maxLocals)
	for i := range pts {
		pts[i] = map[string]bool{}
	}
	if !flowSafe {
		for i := range unknown {
			unknown[i] = true
		}
		return pts, unknown
	}
	for _, slot := range parameterLocalSlots(access, desc) {
		if slot >= 0 && slot < maxLocals {
			unknown[slot] = true
		}
	}
	var edges []inclusionEdge
	for i := 0; i < len(ins); i++ {
		cur := ins[i]
		if cur.op >= 0x4b && cur.op <= 0x4e {
			to := int(cur.op - 0x4b)
			class, from, known := storedReferenceSource(ins, i, cp)
			applyStoreConstraint(pts, unknown, &edges, to, class, from, known)
		} else if cur.op == 0x3a {
			to := cur.operand
			class, from, known := storedReferenceSource(ins, i, cp)
			applyStoreConstraint(pts, unknown, &edges, to, class, from, known)
		}
	}
	for changed, rounds := true, 0; changed && rounds <= maxLocals*maxLocals+1; rounds++ {
		changed = false
		for _, e := range edges {
			if e.from < 0 || e.from >= maxLocals || e.to < 0 || e.to >= maxLocals {
				continue
			}
			if unknown[e.from] && !unknown[e.to] {
				unknown[e.to] = true
				changed = true
			}
			for typ := range pts[e.from] {
				if !pts[e.to][typ] {
					pts[e.to][typ] = true
					changed = true
				}
			}
		}
	}
	return pts, unknown
}

func applyStoreConstraint(pts []map[string]bool, unknown []bool, edges *[]inclusionEdge, to int, class string, from int, known bool) {
	if to < 0 || to >= len(pts) {
		return
	}
	switch {
	case class != "":
		pts[to][class] = true
	case from >= 0:
		*edges = append(*edges, inclusionEdge{from: from, to: to})
	case !known:
		unknown[to] = true
	}
}

func instructionAt(ins []instruction, idx int) (instruction, bool) {
	if idx < 0 {
		return instruction{}, false
	}
	for i, in := range ins {
		if i == idx {
			return in, true
		}
	}
	return instruction{}, false
}

func storedReferenceSource(ins []instruction, storeIdx int, cp parsedCP) (class string, from int, known bool) {
	if storeIdx <= 0 || storeIdx >= len(ins) {
		return "", -1, false
	}
	j := storeIdx - 1
	cur, ok := instructionAt(ins, j)
	if !ok {
		return "", -1, false
	}
	if j > 0 && cur.op == 0xc0 {
		j--
		cur, ok = instructionAt(ins, j)
		if !ok {
			return "", -1, false
		}
	}
	if local, ok := aloadLocal(cur); ok {
		return "", local, true
	}
	if storeIdx >= 3 {
		window := ins[storeIdx-3 : storeIdx]
		if window[0].op == 0xbb && window[1].op == 0x59 && window[2].op == 0xb7 {
			allocated := cp.className(window[0].cpIndex)
			owner, name, _, ok := cp.member(window[2].cpIndex)
			if ok && name == "<init>" && allocated != "" && owner == allocated {
				return allocated, -1, true
			}
		}
	}
	return "", -1, false
}

func precedingReceiverLocal(ins []instruction, callIdx int) (int, bool) {
	if callIdx <= 0 || callIdx >= len(ins) {
		return 0, false
	}
	j := callIdx - 1
	cur, ok := instructionAt(ins, j)
	if !ok {
		return 0, false
	}
	if j > 0 && cur.op == 0xc0 {
		j--
		cur, ok = instructionAt(ins, j)
		if !ok {
			return 0, false
		}
	}
	return aloadLocal(cur)
}

func aloadLocal(in instruction) (int, bool) {
	switch {
	case in.op == 0x19:
		return in.operand, true
	case in.op >= 0x2a && in.op <= 0x2d:
		return int(in.op - 0x2a), true
	default:
		return 0, false
	}
}

func parameterLocalSlots(access uint16, desc string) []int {
	var out []int
	slot := 0
	if access&accStatic == 0 {
		out = append(out, 0)
		slot = 1
	}
	if len(desc) == 0 || desc[0] != '(' {
		return out
	}
	for i := 1; i < len(desc) && desc[i] != ')'; {
		out = append(out, slot)
		switch desc[i] {
		case 'J', 'D':
			slot += 2
			i++
		case 'L':
			slot++
			if end := strings.IndexByte(desc[i:], ';'); end >= 0 {
				i += end + 1
			} else {
				return out
			}
		case '[':
			slot++
			for i < len(desc) && desc[i] == '[' {
				i++
			}
			if i < len(desc) && desc[i] == 'L' {
				if end := strings.IndexByte(desc[i:], ';'); end >= 0 {
					i += end + 1
				} else {
					return out
				}
			} else {
				i++
			}
		default:
			slot++
			i++
		}
	}
	return out
}

func decodeInstructions(code []byte) ([]instruction, bool, error) {
	var out []instruction
	flowSafe := true
	for off := 0; off < len(code); {
		op := code[off]
		in := instruction{off: off, op: op, operand: -1}
		length, err := instructionLength(code, off)
		if err != nil || length <= 0 || off+length > len(code) {
			return nil, false, fmt.Errorf("%w: malformed bytecode at %d", errMalformed, off)
		}
		switch op {
		case 0x19, 0x3a:
			in.operand = int(code[off+1])
		case 0x12:
			in.cpIndex = uint16(code[off+1])
		case 0x13, 0x14, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbd, 0xc0, 0xc1:
			in.cpIndex = binary.BigEndian.Uint16(code[off+1 : off+3])
		}
		if isControlTransfer(op) {
			flowSafe = false
		}
		out = append(out, in)
		off += length
	}
	return out, flowSafe, nil
}

func isControlTransfer(op byte) bool {
	return (op >= 0x99 && op <= 0xa9) || op == 0xaa || op == 0xab || op == 0xc6 || op == 0xc7 || op == 0xc8 || op == 0xc9
}

func instructionLength(code []byte, off int) (int, error) {
	op := code[off]
	switch op {
	case 0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9, 0xbc:
		return 2, nil
	case 0x11, 0x13, 0x14, 0x84,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7:
		return 3, nil
	case 0xc5:
		return 4, nil
	case 0xb9, 0xba, 0xc8, 0xc9:
		return 5, nil
	case 0xaa:
		pad := (4 - ((off + 1) & 3)) & 3
		base := off + 1 + pad
		if base+12 > len(code) {
			return 0, errMalformed
		}
		low := int32(binary.BigEndian.Uint32(code[base+4 : base+8]))
		high := int32(binary.BigEndian.Uint32(code[base+8 : base+12]))
		if high < low || int64(high)-int64(low) > 1_000_000 {
			return 0, errMalformed
		}
		return 1 + pad + 12 + int(high-low+1)*4, nil
	case 0xab:
		pad := (4 - ((off + 1) & 3)) & 3
		base := off + 1 + pad
		if base+8 > len(code) {
			return 0, errMalformed
		}
		n := int32(binary.BigEndian.Uint32(code[base+4 : base+8]))
		if n < 0 || n > 1_000_000 {
			return 0, errMalformed
		}
		return 1 + pad + 8 + int(n)*8, nil
	case 0xc4:
		if off+2 > len(code) {
			return 0, errMalformed
		}
		if code[off+1] == 0x84 {
			return 6, nil
		}
		return 4, nil
	default:
		return 1, nil
	}
}
