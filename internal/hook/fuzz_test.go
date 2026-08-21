package hook_test

import (
	"testing"

	"github.com/smlx/ambashador/internal/hook"
)

func FuzzValidate(f *testing.F) {
	seeds := []string{
		"ls -la",
		"rm -rf /",
		"sed -n 1p f",
		"ls 2>/dev/null",
		"git status",
		"echo hello | cat",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		dec := hook.Validate(input)
		_, err := dec.JSON()
		if err != nil {
			t.Fatalf("failed to serialize decision: %v", err)
		}
	})
}
