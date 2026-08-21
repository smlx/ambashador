// Package main implements the command-line interface of ambashador.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/smlx/ambashador/internal/hook"
)

// CLI represents the command-line interface.
type CLI struct {
	Command string      `kong:"arg,optional,env='CRUSH_TOOL_INPUT_COMMAND',help='Command string to validate'"`
	Version VersionFlag `kong:"help='Print version information'"`
}

// Run executes the default validation logic.
func (c *CLI) Run(ctx context.Context) error {
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
	ctx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
		kong.BindFor(ctx),
	)
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run())
}
