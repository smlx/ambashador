# Ambashador

[![Release](https://github.com/smlx/ambashador/actions/workflows/release.yaml/badge.svg)](https://github.com/smlx/ambashador/actions/workflows/release.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/smlx/ambashador.svg)](https://pkg.go.dev/github.com/smlx/ambashador)

Opinionated Bash hook for crush.

## Philosophy

Reading/writing files is permitted. Any command that risks arbitrary command execution or network egress falls through to an interactive prompt.
