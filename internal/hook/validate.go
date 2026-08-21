package hook

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SedSandboxAdvice is context advice provided when sed is run without sandbox.
const SedSandboxAdvice = "Use 'sed --sandbox ...' to avoid a " +
	"permission prompt."

// AllowedCommands are commands permitted at the beginning of a pipeline.
var AllowedCommands = map[string]bool{
	"cat":           true,
	"cd":            true,
	"cut":           true,
	"echo":          true,
	"false":         true,
	"find":          true,
	"git":           true,
	"go":            true,
	"gofmt":         true,
	"golangci-lint": true,
	"govulncheck":   true,
	"grep":          true,
	"head":          true,
	"ls":            true,
	"nl":            true,
	"pwd":           true,
	"rg":            true,
	"sed":           true,
	"sort":          true,
	"tail":          true,
	"tee":           true,
	"true":          true,
	"uniq":          true,
	"wc":            true,
}

// AllowedGitSubcommands are read-only git subcommands.
var AllowedGitSubcommands = map[string]bool{
	"diff":   true,
	"show":   true,
	"status": true,
	"log":    true,
}

// AllowedFilters are commands permitted as later stages in a pipeline.
var AllowedFilters = map[string]bool{
	"cat":  true,
	"cut":  true,
	"grep": true,
	"head": true,
	"nl":   true,
	"rg":   true,
	"sed":  true,
	"sort": true,
	"tail": true,
	"tee":  true,
	"uniq": true,
	"wc":   true,
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
	if !isStmtValid(stmt) || stmt.Cmd == nil {
		return Prompt("")
	}
	return checkCommand(stmt.Cmd)
}

func isStmtValid(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Background || stmt.Coprocess || stmt.Negated {
		return false
	}
	if !checkRedirects(stmt.Redirs) {
		return false
	}
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		return checkRedirectsAfterCmd(stmt.Redirs, call)
	}
	return true
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
	return collectPipeStages(b, nil)
}

func collectPipeStages(b *syntax.BinaryCmd, stages []*syntax.Stmt) ([]*syntax.Stmt, bool) {
	if b.Op != syntax.Pipe {
		return nil, false
	}
	if leftBin, ok := b.X.Cmd.(*syntax.BinaryCmd); ok &&
		leftBin.Op == syntax.Pipe &&
		len(b.X.Redirs) == 0 &&
		!b.X.Background &&
		!b.X.Coprocess &&
		!b.X.Negated {
		var ok bool
		stages, ok = collectPipeStages(leftBin, stages)
		if !ok {
			return nil, false
		}
	} else {
		stages = append(stages, b.X)
	}
	stages = append(stages, b.Y)
	return stages, true
}

func checkPipeline(stages []*syntax.Stmt) Decision {
	if len(stages) == 0 {
		return Allow()
	}
	for i, stage := range stages {
		if !isStmtValid(stage) {
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
		if !isAllowedRedirect(r) ||
			(r.Op != syntax.RdrOut &&
				r.Op != syntax.AppOut &&
				r.Op != syntax.RdrAll &&
				r.Op != syntax.AppAll) {
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

// CommandValidator inspects arguments for a specific command and returns a Decision.
type CommandValidator func(args []string) Decision

var commandValidators = map[string]CommandValidator{
	"find": validateFind,
	"git":  validateGit,
	"rg":   validateRg,
	"sed":  validateSed,
}

var disallowedFindFlags = map[string]bool{
	"-exec":    true,
	"-execdir": true,
	"-ok":      true,
	"-okdir":   true,
	"-delete":  true,
}

func validateFind(words []string) Decision {
	for _, word := range words[1:] {
		if disallowedFindFlags[word] {
			return Prompt("")
		}
	}
	return Allow()
}

func validateRg(words []string) Decision {
	for _, word := range words[1:] {
		if word == "--pre" || strings.HasPrefix(word, "--pre=") {
			return Prompt("")
		}
	}
	return Allow()
}

func validateSed(words []string) Decision {
	if !slices.Contains(words, "--sandbox") {
		return Prompt(SedSandboxAdvice)
	}
	return Allow()
}

func validateGit(words []string) Decision {
	if len(words) < 2 {
		return Prompt("")
	}
	if !AllowedGitSubcommands[words[1]] {
		return Prompt("")
	}
	return Allow()
}

func checkCall(call *syntax.CallExpr, allowlist map[string]bool) Decision {
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
	if !allowlist[cmdName] {
		return Prompt("")
	}
	if validator, ok := commandValidators[cmdName]; ok {
		return validator(words)
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
	if r.N != nil {
		fdNum := r.N.Value
		if len(fdNum) != 1 || fdNum[0] < '0' || fdNum[0] > '9' {
			return false
		}
	}
	target, ok := extractStaticWord(r.Word)
	if !ok || target == "" {
		return false
	}
	switch r.Op {
	case syntax.DplOut:
		if r.N != nil {
			return len(target) == 1 && target[0] >= '0' && target[0] <= '9'
		}
		allDigits := true
		for i := 0; i < len(target); i++ {
			if target[i] < '0' || target[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(target) != 1 {
			return false
		}
		return true
	case syntax.DplIn:
		return len(target) == 1 && target[0] >= '0' && target[0] <= '9'
	case syntax.RdrOut,
		syntax.AppOut,
		syntax.RdrIn,
		syntax.RdrInOut,
		syntax.RdrClob,
		syntax.RdrAll,
		syntax.AppAll:
		return true
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
			if p.Dollar {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", false
			}
			for _, dp := range p.Parts {
				switch d := dp.(type) {
				case *syntax.Lit:
					if strings.Contains(d.Value, `\`) {
						return "", false
					}
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
