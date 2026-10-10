// Package netcmd recognises shell commands that reach for the network.
package netcmd

import "regexp"

var (
	netRE = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|netcat|socat|telnet|scp|sftp|rsync|ssh|ftp|tftp)\b|https?://|/dev/(tcp|udp)/|\b(requests|urllib|urlopen|http\.client|socket)\b`)
	urlRE = regexp.MustCompile(`(?i)(?:https?|ftp)://[^\s'"` + "`" + `)]+`)
)

// IsNet reports whether a shell command opens a network connection or ships data out.
func IsNet(cmd string) bool { return netRE.MatchString(cmd) }

// URLs returns the URLs mentioned in a command.
func URLs(cmd string) []string { return urlRE.FindAllString(cmd, -1) }
