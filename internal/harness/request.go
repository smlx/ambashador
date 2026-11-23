// Package harness implements PreToolUse request parsing, harness detection,
// and response formatting for Crush and Claude Code.
package harness

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"strings"

	"github.com/smlx/ambashador/internal/hook"
)

const (
	// preToolUse is the hook event name handled for both Crush and Claude Code.
	preToolUse = "PreToolUse"
	// maxHookInputLen bounds the stdin payload size read from a harness.
	maxHookInputLen = 1 << 20
	// toolNameCrush identifies the Crush bash tool.
	toolNameCrush = "bash"
	// toolNameClaude identifies the Claude Code Bash tool.
	toolNameClaude = "Bash"
	// emptyResponse is the fall-through JSON object returned on error or no-op.
	emptyResponse = "{}"
)

// request represents a PreToolUse JSON hook payload from a supported harness.
type request struct {
	Event          jsontext.Value            `json:"event"`
	HookEventName  string                    `json:"hook_event_name"`
	ToolName       string                    `json:"tool_name"`
	ToolInput      map[string]jsontext.Value `json:"tool_input"`
	PermissionMode jsontext.Value            `json:"permission_mode"`
	command        string
}

// Handle reads a PreToolUse hook request from in, validates the extracted
// command, and returns a harness-formatted JSON response.
func Handle(in io.Reader) []byte {
	req := readRequest(in)
	decision := hook.Validate(req.command)
	var response []byte
	var err error
	if req.ToolName == toolNameClaude {
		response, err = claudeResponse(req, decision)
	} else {
		response, err = crushResponse(decision)
	}
	if err != nil {
		return []byte(emptyResponse)
	}
	return response
}

// HandleCommand validates a raw command string and returns a Crush-formatted
// JSON response.
func HandleCommand(command string) []byte {
	decision := hook.Validate(command)
	response, err := crushResponse(decision)
	if err != nil {
		return []byte(emptyResponse)
	}
	return response
}

// readRequest decodes and validates a PreToolUse hook payload from in.
func readRequest(in io.Reader) request {
	data, err := io.ReadAll(io.LimitReader(in, maxHookInputLen+1))
	if err != nil || len(data) == 0 || len(data) > maxHookInputLen {
		return request{}
	}

	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		return request{}
	}
	switch req.ToolName {
	case toolNameCrush:
		var event string
		if err := json.Unmarshal(req.Event, &event); err != nil ||
			event != preToolUse ||
			(req.HookEventName != "" && req.HookEventName != preToolUse) {
			return request{}
		}
	case toolNameClaude:
		if req.Event != nil || req.HookEventName != preToolUse {
			return request{}
		}
	default:
		return request{}
	}

	if err := json.Unmarshal(req.ToolInput["command"], &req.command); err != nil ||
		strings.TrimSpace(req.command) == "" {
		return request{}
	}
	return req
}
