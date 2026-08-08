package fleetversion

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want Version
	}{
		{"1.2.3", true, Version{1, 2, 3}},
		{"v1.2.3", true, Version{1, 2, 3}},
		{"0.1.0", true, Version{0, 1, 0}},
		{"1.2", true, Version{1, 2, 0}},
		{"2", true, Version{2, 0, 0}},
		{"1.2.3-rc1", true, Version{1, 2, 3}},
		{"1.2.3+build.5", true, Version{1, 2, 3}},
		{"  v2.0.1  ", true, Version{2, 0, 1}},
		{"", false, Version{}},
		{"x.y.z", false, Version{}},
		{"1.2.3.4", false, Version{}},
		{"1..3", false, Version{}},
		{"-1.0.0", false, Version{}},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("Parse(%q) = %+v,%v; want %+v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCompareAndLess(t *testing.T) {
	mk := func(s string) Version { v, _ := Parse(s); return v }
	if mk("1.2.3").Compare(mk("1.2.3")) != 0 {
		t.Error("equal versions must compare 0")
	}
	if !mk("1.2.3").Less(mk("1.2.4")) || !mk("1.2.9").Less(mk("1.3.0")) || !mk("1.9.9").Less(mk("2.0.0")) {
		t.Error("older versions must be Less")
	}
	if mk("2.0.0").Less(mk("1.9.9")) {
		t.Error("newer must not be Less")
	}
}

func TestMeetsFloor(t *testing.T) {
	cases := []struct {
		version, floor string
		want           bool
	}{
		{"1.2.3", "", true},         // no floor
		{"1.2.3", "1.2.3", true},    // equal meets
		{"1.3.0", "1.2.9", true},    // above
		{"1.2.2", "1.2.3", false},   // below
		{"0.0.1", "0.1.0", false},   // below
		{"", "1.0.0", false},        // active floor + empty/unparseable version => fail closed
		{"garbage", "1.0.0", false}, // active floor + unparseable version => fail closed
		{"1.0.0", "garbage", true},  // malformed floor => no enforceable floor
		{"garbage", "", true},       // no floor => always ok regardless of version
	}
	for _, c := range cases {
		if got := MeetsFloor(c.version, c.floor); got != c.want {
			t.Errorf("MeetsFloor(%q,%q) = %v; want %v", c.version, c.floor, got, c.want)
		}
	}
}
