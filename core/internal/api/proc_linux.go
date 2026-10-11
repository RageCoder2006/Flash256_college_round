package api

import "syscall"

// killGroup signals the run's whole process group (the run was started with Setpgid), so sandboxed agents stop with it.
func killGroup(pid int, hard bool) error {
	sig := syscall.SIGINT
	if hard {
		sig = syscall.SIGKILL
	}
	return syscall.Kill(-pid, sig)
}
