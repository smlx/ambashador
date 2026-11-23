// Package main implements the command-line interface of ambashador.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/smlx/ambashador/internal/harness"
)

// CLI represents the command-line interface.
type CLI struct {
	Command *string     `kong:"arg,optional,help='Command string to validate'"`
	Version VersionFlag `kong:"help='Print version information'"`
}

// Run executes the default validation logic.
func (c *CLI) Run(in io.Reader, out io.Writer) error {
	var response []byte
	if c.Command != nil {
		response = harness.HandleCommand(*c.Command)
	} else {
		response = harness.Handle(in)
	}
	_, err := fmt.Fprintln(out, string(response))
	return err
}

func redirectedInput(file *os.File) io.Reader {
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return strings.NewReader("")
	}
	return file
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
		kong.BindTo(redirectedInput(os.Stdin), (*io.Reader)(nil)),
		kong.BindTo(os.Stdout, (*io.Writer)(nil)),
	)
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run())
}
