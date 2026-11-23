# Ambashador

[![Release](https://github.com/smlx/ambashador/actions/workflows/release.yaml/badge.svg)](https://github.com/smlx/ambashador/actions/workflows/release.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/smlx/ambashador.svg)](https://pkg.go.dev/github.com/smlx/ambashador)

Opinionated Bash hook for crush.

## Philosophy

Reading/writing files is permitted. Any command that risks arbitrary command execution or network egress falls through to an interactive prompt.

Auto-approved Git commands are rewritten with `-c core.fsmonitor=false` so that Git does not run a configured filesystem monitor. This requires Git 2.36 or later; older versions may interpret `false` as a hook path. This override does not disable other Git helpers.

Archive inspection is auto-approved only for `tar -xOzf` on a literal local archive and a literal member name. The hook clears `TAR_OPTIONS` for that invocation. Shell loops and commands with variable arguments still require approval.
