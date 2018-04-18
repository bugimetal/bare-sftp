// +build !darwin,!linux

package bsftp

import (
	"syscall"
)

func (p sshFxpExtendedPacketStatVFS) respond(svr *Server) error {
	return syscall.ENOTSUP
}
