//go:build !linux

package egressbroker

import (
	"errors"
	"net"
)

type peerIdentity struct {
	pid int
	uid int
	gid int
}

type sandboxProcess struct{}

func peerIdentityFromConn(net.Conn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("egress broker peer authentication is Linux-only")
}

func authorizeSandboxProcess(peerIdentity, int, int, string) (*sandboxProcess, error) {
	return nil, errors.New("egress broker sandbox authorization is Linux-only")
}

func (*sandboxProcess) Alive() error {
	return errors.New("egress broker sandbox authorization is Linux-only")
}

func (*sandboxProcess) NetworkNamespaceFD() int { return -1 }

func (*sandboxProcess) Close() error { return nil }
