//go:build !linux

package ruleconvert

import "syscall"

func socketControl(uint32) func(string, string, syscall.RawConn) error { return nil }
