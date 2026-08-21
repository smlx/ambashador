package hook_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/smlx/ambashador/internal/hook"
)

func TestValidateCases(t *testing.T) {
	file, err := os.Open("testdata/bash-prompt-cases.tsv")
	assert.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		assert.Equal(t, 2, len(parts), "malformed test case line %d: %q",
			lineNo, line)

		expectation := parts[0]
		cmd := strings.ReplaceAll(parts[1], `\n`, "\n")

		t.Run(expectation+": "+cmd, func(t *testing.T) {
			dec := hook.Validate(cmd)
			b, err := dec.JSON()
			assert.NoError(t, err)
			got := string(b)

			switch expectation {
			case "allow":
				assert.Equal(t, `{"decision":"allow"}`, got)
			case "deny":
				assert.Equal(t, "{}", got)
			case "explain":
				assert.Equal(t, hook.Prompt(hook.SedSandboxAdvice), dec)
				assert.Equal(t,
					`{"context":"`+hook.SedSandboxAdvice+`"}`, got)
			default:
				t.Fatalf("unexpected expectation: %s", expectation)
			}
		})
	}
	assert.NoError(t, scanner.Err())
}

func TestValidateEmptyAndUnset(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		dec := hook.Validate("")
		assert.Equal(t, hook.Prompt(""), dec)
		b, err := dec.JSON()
		assert.NoError(t, err)
		assert.Equal(t, "{}", string(b))
	})

	t.Run("whitespace only", func(t *testing.T) {
		dec := hook.Validate("   \t  \n  ")
		assert.Equal(t, hook.Prompt(""), dec)
		b, err := dec.JSON()
		assert.NoError(t, err)
		assert.Equal(t, "{}", string(b))
	})
}
