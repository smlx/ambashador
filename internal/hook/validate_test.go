package hook_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
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
		parts := strings.SplitN(line, "\t", 3)
		assert.True(t, len(parts) >= 2, "malformed test case line %d: %q",
			lineNo, line)

		expectation := parts[0]
		cmd := strings.ReplaceAll(parts[1], `\n`, "\n")

		t.Run(expectation+": "+cmd, func(t *testing.T) {
			dec := hook.Validate(cmd)

			switch expectation {
			case "allow":
				assert.Equal(t, hook.Allow(), dec)
			case "rewrite":
				assert.Equal(t, 3, len(parts))
				assert.True(t, dec.IsAllowed())
				assert.Equal(t, map[string]string{
					"command": strings.ReplaceAll(parts[2], `\n`, "\n"),
				}, dec.UpdatedInput)
			case "deny":
				assert.Equal(t, hook.Prompt(""), dec)
			case "explain":
				assert.Equal(t, hook.Prompt(hook.SedSandboxAdvice), dec)
			default:
				t.Fatalf("unexpected expectation: %s", expectation)
			}
		})
	}
	assert.NoError(t, scanner.Err())
}

func TestGitRewriteDisablesConfiguredFSMonitor(t *testing.T) {
	for _, name := range []string{"bash", "git", "true"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s unavailable: %v", name, err)
		}
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "empty-config"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_TRACE", "1")
	run := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), name, args...)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		assert.NoError(t, err, "%s", output)
		return string(output)
	}
	run("git", "init", "--quiet")
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "lockfile"), []byte("line\n"), 0o600))
	run("git", "add", "lockfile")
	run("git", "config", "core.fsmonitor", "true 2>/dev/null")
	original := "git ls-files '*lock*'"
	assert.Contains(t, run("bash", "-c", original), "run_command:")
	decision := hook.Validate(original)
	assert.Equal(t, hook.Decision{
		Decision: "allow",
		UpdatedInput: map[string]string{
			"command": "git -c core.fsmonitor=false ls-files -- '*lock*'",
		},
	}, decision)
	output := run("bash", "-c", decision.UpdatedInput["command"])
	assert.Contains(t, output, "lockfile\n")
	assert.False(t, strings.Contains(output, "run_command:"), "%s", output)
}

func TestValidateEmptyAndUnset(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		dec := hook.Validate("")
		assert.Equal(t, hook.Prompt(""), dec)
	})

	t.Run("whitespace only", func(t *testing.T) {
		dec := hook.Validate("   \t  \n  ")
		assert.Equal(t, hook.Prompt(""), dec)
	})
}
