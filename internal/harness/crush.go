package harness

import (
	"encoding/json/v2"
	"fmt"

	"github.com/smlx/ambashador/internal/hook"
)

// crushOutput represents the JSON response payload expected by Crush.
type crushOutput struct {
	Decision     string            `json:"decision,omitzero"`
	Context      string            `json:"context,omitzero"`
	UpdatedInput map[string]string `json:"updated_input,omitzero"`
}

// crushResponse serializes a validation decision into Crush's wire format.
func crushResponse(decision hook.Decision) ([]byte, error) {
	output := crushOutput{
		Decision:     decision.Decision,
		Context:      decision.Context,
		UpdatedInput: decision.UpdatedInput,
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal crush response: %w", err)
	}
	return encoded, nil
}
