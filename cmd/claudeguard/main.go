// Command claudeguard sends the Claude desktop app and Claude Code through
// a proxy of your choice and blocks every other way to Anthropic.
package main

import (
	"os"

	"github.com/VitalyDubovets/claudeguard/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
