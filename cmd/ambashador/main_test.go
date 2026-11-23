package main_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/kong"
	ambashador "github.com/smlx/ambashador/cmd/ambashador"
)

const crushInput = `{"event":"PreToolUse","hook_event_name":"PreToolUse",` +
	`"tool_name":"bash","tool_input":{"command":"pwd","timeout":1000}}`

const claudeInput = `{"hook_event_name":"PreToolUse","tool_name":"Bash",` +
	`"permission_mode":"default","tool_input":{"command":"pwd",` +
	`"description":"Inspect files","timeout":1000,"run_in_background":false}}`

const claudeAllow = `{"hookSpecificOutput":{"hookEventName":"PreToolUse",` +
	`"permissionDecision":"allow"}}`

type forbiddenReader struct {
	test *testing.T
}

func (r forbiddenReader) Read([]byte) (int, error) {
	r.test.Fatal("unexpected stdin read")
	return 0, io.EOF
}

func runCLI(t *testing.T, in io.Reader, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	app, err := kong.New(&ambashador.CLI{},
		kong.BindTo(in, (*io.Reader)(nil)),
		kong.BindTo(&out, (*io.Writer)(nil)),
	)
	assert.NoError(t, err)
	ctx, err := app.Parse(args)
	assert.NoError(t, err)
	assert.NoError(t, ctx.Run())
	return strings.TrimSuffix(out.String(), "\n")
}

func TestInvocationPrecedence(t *testing.T) {
	t.Setenv("CRUSH_TOOL_INPUT_COMMAND", "sed -n p")
	t.Setenv("CRUSH_EVENT", "PreToolUse")
	t.Setenv("CRUSH_TOOL_NAME", "bash")
	assert.Equal(t, `{"decision":"allow"}`, runCLI(t, forbiddenReader{t}, "pwd"))
	assert.Equal(t, `{}`, runCLI(t, forbiddenReader{t}, ""))
	assert.Equal(t, `{"decision":"allow"}`, runCLI(t, strings.NewReader(crushInput)))
	assert.Equal(t, claudeAllow, runCLI(t, strings.NewReader(claudeInput)))
	assert.Equal(t, `{}`, runCLI(t, strings.NewReader("")))
}

func TestRedirectedInput(t *testing.T) {
	file, err := os.Open(os.DevNull)
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, file.Close()) })
	assert.False(t, ambashador.RedirectedInput(file) == file)

	reader, writer, err := os.Pipe()
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reader.Close()) })
	t.Cleanup(func() { assert.NoError(t, writer.Close()) })
	assert.True(t, ambashador.RedirectedInput(reader) == reader)
}
