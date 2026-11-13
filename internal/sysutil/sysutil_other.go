//go:build !darwin && !windows && !linux

package sysutil

import (
	"os/exec"
	"strconv"
	"strings"
)

func IsRoot() bool { return false }

func HideChildWindow(*exec.Cmd) {}

func ListenerPID(port int) int {
	out, _ := exec.Command("lsof", "-nP", "-a", "-iTCP@127.0.0.1:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fp").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			pid, _ := strconv.Atoi(line[1:])
			return pid
		}
	}
	return 0
}
