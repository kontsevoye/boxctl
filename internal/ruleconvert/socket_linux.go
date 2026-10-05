//go:build linux

package ruleconvert

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func socketControl(mark uint32) func(string, string, syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(_, _ string, conn syscall.RawConn) error {
		var socketErr error
		err := conn.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)) })
		if err != nil {
			return err
		}
		return socketErr
	}
}
