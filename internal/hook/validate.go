package hook

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SedSandboxAdvice is context advice provided when sed is run without sandbox.
const SedSandboxAdvice = "Use 'sed --sandbox ...' to avoid a " +
	"permission prompt."

// AllowedCommands are commands permitted at the beginning of a pipeline.
var AllowedCommands = map[string]struct{}{
	"cat":           {},
	"cd":            {},
	"echo":          {},
	"false":         {},
	"find":          {},
	"git":           {},
	"go":            {},
	"gofmt":         {},
	"golangci-lint": {},
	"govulncheck":   {},
	"grep":          {},
	"head":          {},
	"ls":            {},
	"pwd":           {},
	"rg":            {},
	"sed":           {},
	"tail":          {},
	"tee":           {},
	"true":          {},
}

// AllowedGitSubcommands are read-only git subcommands.
var AllowedGitSubcommands = map[string]struct{}{
	"diff":   {},
	"show":   {},
	"status": {},
	"log":    {},
}

// AllowedFilters are commands permitted as later stages in a pipeline.
var AllowedFilters = map[string]struct{}{
	"cat":  {},
	"cut":  {},
	"grep": {},
	"head": {},
	"nl":   {},
	"rg":   {},
	"sed":  {},
	"sort": {},
	"tail": {},
	"tee":  {},
	"uniq": {},
	"wc":   {},
}

// Validate inspects a shell command and determines whether it can be approved.
func Validate(cmd string) Decision {
	if strings.TrimSpace(cmd) == "" {
		return Prompt("")
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return Prompt("")
	}
	if len(file.Stmts) == 0 {
		return Prompt("")
	}
	for _, stmt := range file.Stmts {
		dec := checkStmt(stmt)
		if dec.Decision != "allow" {
			return dec
		}
	}
	return Allow()
}

func checkStmt(stmt *syntax.Stmt) Decision {
	if stmt == nil || stmt.Background || stmt.Coprocess || stmt.Negated {
		return Prompt("")
	}
	if !checkRedirects(stmt.Redirs) {
		return Prompt("")
	}
	if stmt.Cmd == nil {
		return Prompt("")
	}
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		if !checkRedirectsAfterCmd(stmt.Redirs, call) {
			return Prompt("")
		}
	}
	return checkCommand(stmt.Cmd)
}

func checkCommand(cmd syntax.Command) Decision {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return checkCall(c, AllowedCommands)
	case *syntax.BinaryCmd:
		return checkBinaryCmd(c)
	default:
		return Prompt("")
	}
}

func checkBinaryCmd(b *syntax.BinaryCmd) Decision {
	switch b.Op {
	case syntax.AndStmt, syntax.OrStmt:
		dec := checkStmt(b.X)
		if dec.Decision != "allow" {
			return dec
		}
		return checkStmt(b.Y)
	case syntax.Pipe:
		calls, ok := flattenPipeline(b)
		if !ok {
			return Prompt("")
		}
		return checkPipeline(calls)
	default:
		return Prompt("")
	}
}

func flattenPipeline(b *syntax.BinaryCmd) ([]*syntax.Stmt, bool) {
	var stages []*syntax.Stmt
	if !collectPipeStages(b, &stages) {
		return nil, false
	}
	return stages, true
}

func collectPipeStages(b *syntax.BinaryCmd, stages *[]*syntax.Stmt) bool {
	if b.Op != syntax.Pipe {
		return false
	}
	if leftBin, ok := b.X.Cmd.(*syntax.BinaryCmd); ok &&
		leftBin.Op == syntax.Pipe &&
		len(b.X.Redirs) == 0 &&
		!b.X.Background &&
		!b.X.Coprocess &&
		!b.X.Negated {
		if !collectPipeStages(leftBin, stages) {
			return false
		}
	} else {
		*stages = append(*stages, b.X)
	}
	*stages = append(*stages, b.Y)
	return true
}

func checkPipeline(stages []*syntax.Stmt) Decision {
	if len(stages) == 0 {
		return Allow()
	}
	for i, stage := range stages {
		if stage.Background || stage.Coprocess || stage.Negated {
			return Prompt("")
		}
		if !checkRedirects(stage.Redirs) {
			return Prompt("")
		}
		if stage.Cmd == nil {
			if !isDiscardOnlyStage(stage.Redirs) {
				return Prompt("")
			}
			continue
		}
		call, ok := stage.Cmd.(*syntax.CallExpr)
		if !ok {
			return Prompt("")
		}
		if !checkRedirectsAfterCmd(stage.Redirs, call) {
			return Prompt("")
		}
		allowlist := AllowedFilters
		if i == 0 {
			allowlist = AllowedCommands
		}
		dec := checkCall(call, allowlist)
		if dec.Decision != "allow" {
			return dec
		}
	}
	return Allow()
}

func isDiscardOnlyStage(redirs []*syntax.Redirect) bool {
	if len(redirs) == 0 {
		return false
	}
	for _, r := range redirs {
		if r.Op != syntax.RdrOut {
			return false
		}
	}
	return true
}

func checkRedirectsAfterCmd(redirs []*syntax.Redirect, cmd syntax.Command) bool {
	for _, r := range redirs {
		if !r.Pos().After(cmd.Pos()) {
			return false
		}
	}
	return true
}

func checkCall(call *syntax.CallExpr, allowlist map[string]struct{}) Decision {
	if len(call.Assigns) > 0 {
		return Prompt("")
	}
	var words []string
	for _, w := range call.Args {
		lit, ok := extractStaticWord(w)
		if !ok {
			return Prompt("")
		}
		words = append(words, lit)
	}
	if len(words) == 0 {
		return Prompt("")
	}
	cmdName := words[0]
	if _, ok := allowlist[cmdName]; !ok {
		return Prompt("")
	}
	if cmdName == "sed" && !hasWord(words, "--sandbox") {
		return Prompt(SedSandboxAdvice)
	}
	if cmdName == "git" {
		if len(words) < 2 {
			return Prompt("")
		}
		if _, ok := AllowedGitSubcommands[words[1]]; !ok {
			return Prompt("")
		}
	}
	return Allow()
}

func checkRedirects(redirs []*syntax.Redirect) bool {
	for _, r := range redirs {
		if !isAllowedRedirect(r) {
			return false
		}
	}
	return true
}

func isAllowedRedirect(r *syntax.Redirect) bool {
	if r == nil {
		return true
	}
	if r.N == nil {
		return false
	}
	fdNum := r.N.Value
	if len(fdNum) != 1 || fdNum[0] < '0' || fdNum[0] > '9' {
		return false
	}
	switch r.Op {
	case syntax.DplOut, syntax.DplIn:
		target, ok := extractStaticWord(r.Word)
		if !ok {
			return false
		}
		return len(target) == 1 && target[0] >= '0' && target[0] <= '9'
	case syntax.RdrOut:
		target, ok := extractStaticWord(r.Word)
		if !ok {
			return false
		}
		return target == "/dev/null"
	default:
		return false
	}
}

func extractStaticWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if strings.Contains(p.Value, `\`) {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				switch d := dp.(type) {
				case *syntax.Lit:
					b.WriteString(d.Value)
				default:
					return "", false
				}
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func hasWord(words []string, target string) bool {
	for _, w := range words {
		if w == target {
			return true
		}
	}
	return false
}
