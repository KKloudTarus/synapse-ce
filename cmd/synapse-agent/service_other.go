//go:build !windows

package main

import "context"

// runAsService is a no-op off Windows: systemd starts the agent as an ordinary process and needs no
// handshake. It exists so main() has one shape on every platform.
func runAsService(func(context.Context) error) bool { return false }
