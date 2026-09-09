package advisory

import (
	"strconv"
	"strings"
)

// This ports Apache Maven's ComparableVersion (the authority Maven itself uses to order versions) so the
// owned matcher orders Maven version ranges the way Maven does, including the "-" sub-list NESTING a flat
// token comparison gets wrong (e.g. "1-1" < "1.1", because a "-" after a number starts a nested list). A
// version parses into a tree of items: an integer, a string qualifier, or a nested list. A "." separates
// items in the current list; a "-" (and a digit<->letter transition) starts a nested list. Trailing "null"
// items (0, the release qualifier, an empty list) are trimmed so "1.0" == "1" and "1-ga" == "1". Comparison
// is recursive with Maven's cross-type rules, and a list compared to null compares every item (MNG-6964).
//
// SCOPE: this tracks the long-stable Maven 3.x ComparableVersion. It does NOT implement two later, niche
// refinements, because they only reorder exotic forms that do not appear in real advisory version ranges: a
// "." that precedes a non-numeric qualifier is kept flat rather than nested like a "-" (so a "1.0.rc"-style
// tail may order differently from "1.0-rc"), and Maven 4's CombinationItem (which reorders a "1-foo1" vs
// "1-foo.1"-style pair) is absent. Digit detection is ASCII, which is stricter and safe over untrusted input.

type mvnKind int

const (
	mvnInt mvnKind = iota
	mvnString
	mvnList
)

type mvnItem struct {
	kind mvnKind
	num  string     // mvnInt: the digit run, leading zeros stripped ("" means 0)
	str  string     // mvnString: the qualifier
	list []*mvnItem // mvnList: the sub-items
}

// mvnQualifiers is Maven's qualifier order; the empty string is the RELEASE and sits at index 5. An unknown
// qualifier sorts after every listed one (and after release) and ties break lexically.
var mvnQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

const mvnReleaseIndex = "5" // strconv.Itoa(indexOf("")) — the release qualifier's comparable key

// mvnComparableQualifier maps a qualifier to its sort key, applying Maven's aliases (ga/final/release -> "";
// cr -> rc). A listed qualifier yields its index; an unknown one yields "<len>-<qualifier>" so it sorts after
// every listed qualifier and unknown qualifiers order lexically among themselves.
func mvnComparableQualifier(q string) string {
	switch q {
	case "ga", "final", "release":
		q = ""
	case "cr":
		q = "rc"
	}
	for i, known := range mvnQualifiers {
		if known == q {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(mvnQualifiers)) + "-" + q
}

func mvnStripLeadingZeros(num string) string {
	num = strings.TrimLeft(num, "0")
	if num == "" {
		return "0"
	}
	return num
}

func mvnIntItem(num string) *mvnItem {
	if num == "" {
		num = "0"
	}
	return &mvnItem{kind: mvnInt, num: mvnStripLeadingZeros(num)}
}

// mvnStringItem builds a qualifier item. followedByDigit expands Maven's single-letter shorthands (a/b/m)
// that immediately precede a digit into their long forms, matching ComparableVersion.StringItem.
func mvnStringItem(s string, followedByDigit bool) *mvnItem {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	return &mvnItem{kind: mvnString, str: s}
}

func mvnParseItem(isDigit bool, buf string) *mvnItem {
	if isDigit {
		return mvnIntItem(buf)
	}
	return mvnStringItem(buf, false)
}

// mvnIsNull reports whether an item is Maven's "null": the integer 0, the release qualifier, or an empty
// list. Trailing null items are trimmed during normalization so trailing ".0"/"-ga" do not change ordering.
func mvnIsNull(it *mvnItem) bool {
	switch it.kind {
	case mvnInt:
		return it.num == "0"
	case mvnString:
		return mvnComparableQualifier(it.str) == mvnReleaseIndex
	case mvnList:
		return len(it.list) == 0
	}
	return false
}

// mvnNormalize trims trailing null items from a list: a null item is removed; a non-null non-list item stops
// the trim; a non-null list is kept and the trim continues past it (matching ComparableVersion.normalize).
func mvnNormalize(l *mvnItem) {
	for i := len(l.list) - 1; i >= 0; i-- {
		last := l.list[i]
		if mvnIsNull(last) {
			l.list = append(l.list[:i], l.list[i+1:]...)
		} else if last.kind != mvnList {
			break
		}
	}
}

// mvnParse parses a version into the item tree, then normalizes every list bottom-up.
func mvnParse(version string) *mvnItem {
	version = strings.ToLower(version)
	root := &mvnItem{kind: mvnList}
	stack := []*mvnItem{root}
	list := root
	nest := func() {
		nl := &mvnItem{kind: mvnList}
		list.list = append(list.list, nl)
		stack = append(stack, nl)
		list = nl
	}
	isDigit := false
	startIndex := 0
	for i := 0; i < len(version); i++ {
		c := version[i]
		switch {
		case c == '.':
			if i == startIndex {
				list.list = append(list.list, mvnIntItem("0"))
			} else {
				list.list = append(list.list, mvnParseItem(isDigit, version[startIndex:i]))
			}
			startIndex = i + 1
		case c == '-':
			if i == startIndex {
				list.list = append(list.list, mvnIntItem("0"))
			} else {
				list.list = append(list.list, mvnParseItem(isDigit, version[startIndex:i]))
			}
			startIndex = i + 1
			nest()
		case c >= '0' && c <= '9':
			if !isDigit && i > startIndex { // letter run ended, a digit begins: push it and nest
				list.list = append(list.list, mvnStringItem(version[startIndex:i], true))
				startIndex = i
				nest()
			}
			isDigit = true
		default: // any non-digit, non-separator char is a qualifier char
			if isDigit && i > startIndex { // digit run ended, a letter begins: push it and nest
				list.list = append(list.list, mvnParseItem(true, version[startIndex:i]))
				startIndex = i
				nest()
			}
			isDigit = false
		}
	}
	if len(version) > startIndex {
		list.list = append(list.list, mvnParseItem(isDigit, version[startIndex:]))
	}
	for len(stack) > 0 {
		mvnNormalize(stack[len(stack)-1])
		stack = stack[:len(stack)-1]
	}
	return root
}

// mvnCmp compares two items with Maven's cross-type and null rules. A nil argument is Maven's "null" (the
// implicit release/zero that a shorter version pads with). It returns -1, 0, or 1.
func mvnCmp(a, b *mvnItem) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -mvnCmp(b, nil) // missing-left vs present-right: reverse of right vs null
	}
	if b == nil {
		switch a.kind {
		case mvnInt:
			if a.num == "0" {
				return 0
			}
			return 1
		case mvnString:
			return mvnSign(strings.Compare(mvnComparableQualifier(a.str), mvnReleaseIndex))
		case mvnList:
			// MNG-6964: a list vs null compares EVERY item to null (not just the first), so a non-null tail
			// deeper in the list still outranks the padded-out shorter version (e.g. "1-0.1" > "1").
			for _, it := range a.list {
				if d := mvnCmp(it, nil); d != 0 {
					return d
				}
			}
			return 0
		}
	}
	switch a.kind {
	case mvnInt:
		if b.kind == mvnInt {
			return mvnSign(compareNumeric(a.num, b.num))
		}
		return 1 // int > string, int > list
	case mvnString:
		switch b.kind {
		case mvnInt:
			return -1 // string < int
		case mvnString:
			return mvnSign(strings.Compare(mvnComparableQualifier(a.str), mvnComparableQualifier(b.str)))
		default:
			return -1 // string < list
		}
	case mvnList:
		switch b.kind {
		case mvnInt:
			return -1 // list < int
		case mvnString:
			return 1 // list > string
		default:
			n := len(a.list)
			if len(b.list) > n {
				n = len(b.list)
			}
			for i := 0; i < n; i++ {
				var x, y *mvnItem
				if i < len(a.list) {
					x = a.list[i]
				}
				if i < len(b.list) {
					y = b.list[i]
				}
				if d := mvnCmp(x, y); d != 0 {
					return d
				}
			}
			return 0
		}
	}
	return 0
}

func mvnSign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
