// Package hook implements bash command validation and approval logic.
package hook

const decisionAllow = "allow"

// Decision represents the outcome of inspecting a command.
type Decision struct {
	Decision     string
	Context      string
	UpdatedInput map[string]string
}

// IsAllowed returns true if the decision permits command execution.
func (d Decision) IsAllowed() bool {
	return d.Decision == decisionAllow
}

// Allow returns an affirmative approval decision.
func Allow() Decision {
	return Decision{
		Decision: decisionAllow,
	}
}

// Prompt returns a fall-through decision, optionally carrying context advice.
func Prompt(context string) Decision {
	return Decision{
		Context: context,
	}
}
