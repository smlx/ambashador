# Ambashador

[![Release](https://github.com/smlx/ambashador/actions/workflows/release.yaml/badge.svg)](https://github.com/smlx/ambashador/actions/workflows/release.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/smlx/ambashador.svg)](https://pkg.go.dev/github.com/smlx/ambashador)

Opinionated Bash hook for Crush and Claude Code.

Ambashador detects the harness from its `PreToolUse` JSON request on stdin. An
explicit positional command (`ambashador 'pwd'`) takes precedence and produces
Crush-format output. Empty, malformed, or unrelated input produces `{}` and
leaves permissions to the harness. Environment variables are not used as input.

## Configure Crush

With `ambashador` on `PATH`, add this hook to `crush.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "^bash$", "command": "ambashador" }
    ]
  }
}
```

To check the stdin path without launching Crush:

```sh
printf '%s\n' '{"event":"PreToolUse","hook_event_name":"PreToolUse","tool_name":"bash","tool_input":{"command":"pwd"}}' | ambashador
```

The expected output is `{"decision":"allow"}`.

## Configure Claude Code

With `ambashador` on `PATH`, add this hook to `.claude/settings.json` for the
project or `~/.claude/settings.json` for your user:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "ambashador" }]
      }
    ]
  }
}
```

To check the stdin path without launching Claude Code:

```sh
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","permission_mode":"default","tool_input":{"command":"pwd"}}' | ambashador
```

The expected output is `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`.

Claude Code can run its Bash tool under Bash or Zsh. Ambashador only
pre-approves bare `pwd`, `true`, and `false` there, and falls through for
background requests or unrecognized tool options. For Git and tar rewrites,
Ambashador returns the complete tool input with only `command` changed, without
pre-approving it. It does not return rewrites in auto mode or other non-default
permission modes. Claude Code still applies its own permission rules.

## Philosophy

In Crush, the allowlist permits some file operations. Commands not approved by
the hook fall through to Crush's normal permission flow.

Auto-approved Git commands are rewritten with `-c core.fsmonitor=false` so that Git does not run a configured filesystem monitor. This requires Git 2.36 or later; older versions may interpret `false` as a hook path. This override does not disable other Git helpers.

Archive inspection is auto-approved for `tar -tzf` to list a literal local archive and `tar -xOzf` to stream one literal member from a literal local archive. The hook clears `TAR_OPTIONS` for both forms. Shell loops and commands with variable arguments still require approval.
