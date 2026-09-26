package sast

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// The retained-source budget bounds the memory held for cross-file context analysis. A fixed 64 MiB was a
// guess that is wrong in both directions: it binds hard on a monorepo (the three largest repositories in one
// estate hold 112, 120 and 164 MiB of source, so most of each was never scanned and every rule reported
// nothing there) and it leaves almost all of a 32 GiB runner unused on every other repository.
//
// So the default is DERIVED from the memory the process may actually use. The container limit is what binds in
// CI, not the host's total, so the cgroup limit is read first and the host total is the fallback.
const (
	// minSourceBudget is the floor: the historical default, so a small or unreadable environment behaves
	// exactly as before rather than worse.
	minSourceBudget = 64 << 20
	// maxSourceBudget is the ceiling. Retained source is one allocation among several and peak RSS was
	// measured at about 3.3 times the budget (320 MiB retained, 1.05 GiB peak), so this keeps a scan under
	// roughly 1.7 GiB however large the machine is.
	maxSourceBudget = 512 << 20
	// sourceBudgetShare is the fraction of the memory limit the retained source may hold. At one eighth the
	// measured peak lands near half the limit, which leaves room for the rest of the scan and for the
	// toolchain beside it.
	sourceBudgetShare = 8
)

var (
	derivedBudgetOnce sync.Once
	derivedBudget     int64
)

// defaultSourceBudget is the retained-source budget for a machine, computed once.
func defaultSourceBudget() int64 {
	derivedBudgetOnce.Do(func() {
		derivedBudget = budgetFor(processMemoryLimit())
	})
	return derivedBudget
}

// budgetFor turns a memory limit into a budget. A zero or unknown limit keeps the historical default, because
// guessing high on a machine whose size is unknown is how a scan gets killed instead of reporting a bound.
func budgetFor(limit int64) int64 {
	if limit <= 0 {
		return minSourceBudget
	}
	share := limit / sourceBudgetShare
	if share < minSourceBudget {
		return minSourceBudget
	}
	if share > maxSourceBudget {
		return maxSourceBudget
	}
	return share
}

// processMemoryLimit returns the bytes of memory this process may use: the cgroup limit when one is set, and
// the host total otherwise. Zero means neither could be read.
func processMemoryLimit() int64 {
	host := hostMemoryTotal()
	if limit := cgroupMemoryLimit(); limit > 0 && (host == 0 || limit < host) {
		return limit
	}
	return host
}

// cgroupMemoryLimit reads the container memory limit, cgroup v2 first and v1 second. An unset limit reads as
// "max" on v2 and as a sentinel near the word size on v1; both mean the host total applies.
func cgroupMemoryLimit() int64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(data))
		if text == "" || text == "max" {
			continue
		}
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil || value <= 0 {
			continue
		}
		// A v1 unlimited cgroup stores a value near the maximum page-aligned int64; treat it as unset.
		if value > 1<<52 {
			continue
		}
		return value
	}
	return 0
}

// hostMemoryTotal reads MemTotal from /proc/meminfo, in bytes.
func hostMemoryTotal() int64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rest, ok := strings.CutPrefix(scanner.Text(), "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kb <= 0 {
			return 0
		}
		return kb * 1024
	}
	return 0
}
