// Package hook implements bash command validation and approval logic.
package hook

import (
	"encoding/json/v2"
	"fmt"
)

const decisionAllow = "allow"

// Decision represents the outcome of inspecting a command.
type Decision struct {
	Decision string `json:"decision,omitzero"`
	Context  string `json:"context,omitzero"`
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

// JSON serializes the decision to a JSON byte slice.
func (d Decision) JSON() ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal decision: %v", err)
	}
	return b, nil
}
