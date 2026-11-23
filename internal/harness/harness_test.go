package harness_test

import (
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/smlx/ambashador/internal/harness"
)

const crushInput = `{"event":"PreToolUse","hook_event_name":"PreToolUse",` +
	`"tool_name":"bash","tool_input":{"command":"pwd","timeout":1000}}`

const claudeInput = `{"hook_event_name":"PreToolUse","tool_name":"Bash",` +
	`"permission_mode":"default","tool_input":{"command":"pwd",` +
	`"description":"Inspect files","timeout":1000,"run_in_background":false}}`

const claudeAllow = `{"hookSpecificOutput":{"hookEventName":"PreToolUse",` +
	`"permissionDecision":"allow"}}`

func TestInvalidRequests(t *testing.T) {
	for name, input := range map[string]string{
		"wrong event":     strings.ReplaceAll(crushInput, "PreToolUse", "PostToolUse"),
		"wrong tool":      strings.Replace(crushInput, `"bash"`, `"Bash"`, 1),
		"claude event":    strings.Replace(claudeInput, "PreToolUse", "PostToolUse", 1),
		"claude tool":     strings.Replace(claudeInput, `"Bash"`, `"bash"`, 1),
		"claude marker":   `{"event":null,` + claudeInput[1:],
		"conflicting":     strings.Replace(crushInput, "PreToolUse", "PostToolUse", 1),
		"missing command": strings.Replace(crushInput, `"command":"pwd",`, "", 1),
		"nonstring":       strings.Replace(crushInput, `"pwd"`, `false`, 1),
		"blank command":   strings.Replace(crushInput, `"pwd"`, `"  "`, 1),
		"malformed":       "{",
		"whitespace":      " \n",
		"null":            "null",
		"trailing input":  crushInput + `{}`,
		"duplicate key": strings.Replace(
			claudeInput,
			`"command":"pwd"`,
			`"command":"true","command":"pwd"`,
			1,
		),
		"oversized": crushInput + strings.Repeat(" ", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			got := string(harness.Handle(strings.NewReader(input)))
			assert.Equal(t, `{}`, got)
		})
	}
}

func TestCrushResponses(t *testing.T) {
	for _, test := range []struct {
		command string
		want    string
	}{
		{"pwd", `{"decision":"allow"}`},
		{"false || unknown", `{}`},
		{
			"sed -n p",
			`{"context":"Use the --sandbox flag when calling \"sed\": \"sed --sandbox ...\""}`,
		},
		{
			"git ls-files",
			`{"decision":"allow","updated_input":{"command":"git -c core.fsmonitor=false ls-files"}}`,
		},
		{
			"tar -tzf local.tar.gz",
			`{"decision":"allow","updated_input":{"command":"TAR_OPTIONS='' tar -tzf local.tar.gz"}}`,
		},
	} {
		t.Run(test.command, func(t *testing.T) {
			input := strings.Replace(crushInput, "pwd", test.command, 1)
			assert.Equal(t, test.want, string(harness.Handle(strings.NewReader(input))))
			assert.Equal(t, test.want, string(harness.HandleCommand(test.command)))
		})
	}
}
