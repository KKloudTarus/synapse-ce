//go:build !windows

package main

import "os"

func replaceJournalFile(from, to string) error {
	return os.Rename(from, to)
}
