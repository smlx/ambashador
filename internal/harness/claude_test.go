package harness_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/smlx/ambashador/internal/harness"
)

func TestClaudeResponses(t *testing.T) {
	for _, test := range []struct {
		command string
		want    string
	}{
		{"pwd", claudeAllow},
		{"go test ./...", `{}`},
		{"false || unknown", `{}`},
		{
			"sed -n p",
			`{"hookSpecificOutput":{"hookEventName":"PreToolUse",` +
				`"additionalContext":"Use the --sandbox flag when calling \"sed\": \"sed --sandbox ...\""}}`,
		},
	} {
		t.Run(test.command, func(t *testing.T) {
			input := strings.Replace(claudeInput, "pwd", test.command, 1)
			assert.Equal(t, test.want, string(harness.Handle(strings.NewReader(input))))
		})
	}
}

func TestClaudeUnsafeOptionsFallThrough(t *testing.T) {
	for _, input := range []string{
		strings.Replace(
			claudeInput,
			`"run_in_background":false`,
			`"run_in_background":true`,
			1,
		),
		strings.Replace(
			claudeInput,
			`"command":"pwd"`,
			`"command":"pwd","dangerouslyDisableSandbox":true`,
			1,
		),
		strings.Replace(
			claudeInput,
			`"command":"pwd"`,
			`"command":"pwd","future_option":{"enabled":true}`,
			1,
		),
	} {
		assert.Equal(t, `{}`, string(harness.Handle(strings.NewReader(input))))
	}
}

func TestClaudeRewrites(t *testing.T) {
	for _, test := range []struct {
		command string
		rewrite string
	}{
		{"git ls-files", "git -c core.fsmonitor=false ls-files"},
		{"tar -tzf local.tar.gz", "TAR_OPTIONS='' tar -tzf local.tar.gz"},
	} {
		t.Run(test.command, func(t *testing.T) {
			input := strings.Replace(claudeInput, "pwd", test.command, 1)
			input = strings.Replace(
				input,
				`"timeout":1000`,
				`"timeout":1000,"future":{"nested":[1,true]}`,
				1,
			)
			result := harness.Handle(strings.NewReader(input))
			var response struct {
				HookSpecificOutput map[string]jsontext.Value `json:"hookSpecificOutput"`
			}
			assert.NoError(t, json.Unmarshal(result, &response))
			assert.Equal(t, map[string]jsontext.Value{
				"hookEventName": jsontext.Value(`"PreToolUse"`),
				"updatedInput":  response.HookSpecificOutput["updatedInput"],
			}, response.HookSpecificOutput)
			var updated map[string]jsontext.Value
			assert.NoError(
				t,
				json.Unmarshal(response.HookSpecificOutput["updatedInput"], &updated),
			)
			command, err := json.Marshal(test.rewrite)
			assert.NoError(t, err)
			assert.Equal(t, map[string]jsontext.Value{
				"command":           command,
				"description":       jsontext.Value(`"Inspect files"`),
				"timeout":           jsontext.Value(`1000`),
				"run_in_background": jsontext.Value(`false`),
				"future":            jsontext.Value(`{"nested":[1,true]}`),
			}, updated)

			autoMode := strings.Replace(input, `"default"`, `"auto"`, 1)
			assert.Equal(t, `{}`, string(harness.Handle(strings.NewReader(autoMode))))
		})
	}
}
