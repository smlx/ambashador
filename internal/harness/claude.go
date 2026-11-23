package harness

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"

	"github.com/smlx/ambashador/internal/hook"
)

// claudeOutput represents the hookSpecificOutput payload for Claude Code.
type claudeOutput struct {
	HookEventName      string                    `json:"hookEventName"`
	PermissionDecision string                    `json:"permissionDecision,omitempty"`
	AdditionalContext  string                    `json:"additionalContext,omitempty"`
	UpdatedInput       map[string]jsontext.Value `json:"updatedInput,omitempty"`
}

// claudeEnvelope wraps Claude Code's hookSpecificOutput response object.
type claudeEnvelope struct {
	HookSpecificOutput *claudeOutput `json:"hookSpecificOutput,omitempty"`
}

// claudeResponse formats a validation decision into Claude Code's wire format
// while enforcing Claude-specific approval and rewrite restrictions.
func claudeResponse(req request, decision hook.Decision) ([]byte, error) {
	output := claudeOutput{
		HookEventName:     preToolUse,
		AdditionalContext: decision.Context,
	}
	if command, rewritten := decision.UpdatedInput["command"]; rewritten {
		if req.permitsClaudeRewrite() {
			encoded, err := json.Marshal(command)
			if err != nil {
				return nil, fmt.Errorf("couldn't marshal rewritten command: %w", err)
			}
			output.UpdatedInput = maps.Clone(req.ToolInput)
			output.UpdatedInput["command"] = encoded
		}
	} else if decision.IsAllowed() && req.canApproveClaudeCommand() {
		output.PermissionDecision = decision.Decision
	}

	var envelope claudeEnvelope
	if output.PermissionDecision != "" ||
		output.AdditionalContext != "" ||
		output.UpdatedInput != nil {
		envelope.HookSpecificOutput = &output
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal claude response: %w", err)
	}
	return encoded, nil
}

// permitsClaudeRewrite reports whether the request's permission_mode allows
// returning a rewritten tool input.
func (req request) permitsClaudeRewrite() bool {
	var mode string
	if req.PermissionMode != nil {
		if err := json.Unmarshal(req.PermissionMode, &mode); err != nil {
			return false
		}
	}
	return mode == "" || mode == "default" || mode == "manual"
}

// canApproveClaudeCommand reports whether the command and tool options are
// eligible for automatic approval in Claude Code.
func (req request) canApproveClaudeCommand() bool {
	switch req.command {
	case "pwd", "true", "false":
	default:
		return false
	}
	for name, value := range req.ToolInput {
		switch name {
		case "command", "description", "timeout":
		case "run_in_background":
			if string(value) != "false" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
