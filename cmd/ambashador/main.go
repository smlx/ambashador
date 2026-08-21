// Package main implements the command-line interface of ambashador.
package main

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/smlx/ambashador/internal/hook"
)

// CLI represents the command-line interface.
type CLI struct {
	Command string      `kong:"arg,optional,env='CRUSH_TOOL_INPUT_COMMAND',help='Command string to validate'"`
	Version VersionFlag `kong:"help='Print version information'"`
}

// Run executes the default validation logic.
func (c *CLI) Run() error {
	dec := hook.Validate(c.Command)
	b, err := dec.JSON()
	if err != nil {
		fmt.Println("{}")
		return nil
	}
	fmt.Println(string(b))
	return nil
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
	)
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run())
}
