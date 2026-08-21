package hook

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SedSandboxAdvice is context advice provided when sed is run without sandbox.
const SedSandboxAdvice = "Use 'sed --sandbox ...' to avoid a permission prompt."

// CommandValidator inspects arguments for a specific command and returns a Decision.
type CommandValidator func(args []string) Decision

// commandValidators registers specialized validation handlers for commands
// requiring deeper argument inspection.
var commandValidators = map[string]CommandValidator{
	"find": validateFind,
	"git":  validateGit,
	"rg":   validateRg,
	"sed":  validateSed,
}

// disallowedFindFlags identifies find arguments capable of file modification or
// arbitrary command execution.
var disallowedFindFlags = map[string]bool{
	"-exec":    true,
	"-execdir": true,
	"-ok":      true,
	"-okdir":   true,
	"-delete":  true,
}

// allowedCommands defines commands permitted at the beginning of a pipeline or command chain.
var allowedCommands = map[string]bool{
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

// allowedGitSubcommands defines read-only git subcommands permitted for auto-approval.
var allowedGitSubcommands = map[string]bool{
	"diff":   true,
	"show":   true,
	"status": true,
	"log":    true,
}

// allowedFilters defines commands permitted as downstream stages within a pipeline.
var allowedFilters = map[string]bool{
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

// Validate inspects a shell command string and determines if auto-approval is
// permissible based on command structure, AST composition, and allowlists.
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
		if !dec.IsAllowed() {
			return dec
		}
	}
	return Allow()
}

// checkStmt validates a top-level shell statement and delegates execution
// inspection to command handlers.
func checkStmt(stmt *syntax.Stmt) Decision {
	if !isStmtValid(stmt) || stmt.Cmd == nil {
		return Prompt("")
	}
	return checkCommand(stmt.Cmd)
}

// isStmtValid verifies statement-level constraints such as absence of
// background execution, coprocesses, negation, and invalid redirection placement.
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

// checkCommand dispatches evaluation based on the AST command node type.
func checkCommand(cmd syntax.Command) Decision {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return checkCall(c, allowedCommands)
	case *syntax.BinaryCmd:
		return checkBinaryCmd(c)
	default:
		return Prompt("")
	}
}

// checkBinaryCmd inspects binary operators, handling conditional chains (AND/OR)
// and pipelines.
func checkBinaryCmd(b *syntax.BinaryCmd) Decision {
	switch b.Op {
	case syntax.AndStmt, syntax.OrStmt:
		dec := checkStmt(b.X)
		if !dec.IsAllowed() {
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

// flattenPipeline decomposes nested binary pipe expressions into a sequential
// slice of pipeline stages.
func flattenPipeline(b *syntax.BinaryCmd) ([]*syntax.Stmt, bool) {
	return collectPipeStages(b, nil)
}

// collectPipeStages recursively collects pipeline stages while ensuring each
// intermediate stage contains valid redirection and control flags.
func collectPipeStages(
	b *syntax.BinaryCmd,
	stages []*syntax.Stmt,
) ([]*syntax.Stmt, bool) {
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

// checkPipeline validates every stage of a pipeline against the appropriate
// initial-command or downstream-filter allowlist.
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
		allowlist := allowedFilters
		if i == 0 {
			allowlist = allowedCommands
		}
		dec := checkCall(call, allowlist)
		if !dec.IsAllowed() {
			return dec
		}
	}
	return Allow()
}

// checkRedirects ensures all file redirections on a statement conform to allowed
// operations and safe static targets.
func checkRedirects(redirs []*syntax.Redirect) bool {
	for _, r := range redirs {
		if !isAllowedRedirect(r) {
			return false
		}
	}
	return true
}

// checkRedirectsAfterCmd confirms redirection operators appear strictly after
// the command expression to prevent argument confusion.
func checkRedirectsAfterCmd(
	redirs []*syntax.Redirect,
	cmd syntax.Command,
) bool {
	for _, r := range redirs {
		if !r.Pos().After(cmd.Pos()) {
			return false
		}
	}
	return true
}

// isDiscardOnlyStage checks if a commandless pipeline stage consists solely of
// standard output/error discard redirections.
func isDiscardOnlyStage(redirs []*syntax.Redirect) bool {
	if len(redirs) == 0 {
		return false
	}
	for _, r := range redirs {
		if !isAllowedRedirect(r) {
			return false
		}
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
		default:
			return false
		}
	}
	return true
}

// isSingleDigit verifies whether a string represents a single ASCII decimal digit.
func isSingleDigit(s string) bool {
	return len(s) == 1 && s[0] >= '0' && s[0] <= '9'
}

// isAllowedRedirect evaluates whether a redirection operator and its target
// descriptor or path meet security criteria without arbitrary expansions.
func isAllowedRedirect(r *syntax.Redirect) bool {
	if r == nil {
		return true
	}
	if r.N != nil && !isSingleDigit(r.N.Value) {
		return false
	}
	target, ok := extractStaticWord(r.Word)
	if !ok || target == "" {
		return false
	}
	switch r.Op {
	case syntax.DplOut:
		if r.N != nil {
			return isSingleDigit(target)
		}
		allDigits := true
		for i := 0; i < len(target); i++ {
			if target[i] < '0' || target[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && !isSingleDigit(target) {
			return false
		}
		return true
	case syntax.DplIn:
		return isSingleDigit(target)
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

// extractLit validates that a literal string contains no escape characters.
func extractLit(v string) (string, bool) {
	if strings.Contains(v, `\`) {
		return "", false
	}
	return v, true
}

// extractStaticWord extracts literal text from a word node, rejecting
// expansions, variable interpolations, or dynamic shell constructs.
func extractStaticWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			lit, ok := extractLit(p.Value)
			if !ok {
				return "", false
			}
			b.WriteString(lit)
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
					lit, ok := extractLit(d.Value)
					if !ok {
						return "", false
					}
					b.WriteString(lit)
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

// checkCall inspects an individual command invocation against the specified
// allowlist and any command-specific validation rules.
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

// validateFind verifies that find invocations do not include execution or deletion flags.
func validateFind(words []string) Decision {
	for _, word := range words[1:] {
		if disallowedFindFlags[word] {
			return Prompt("")
		}
	}
	return Allow()
}

// validateRg ensures ripgrep invocations do not execute preprocessors via --pre flags.
func validateRg(words []string) Decision {
	for _, word := range words[1:] {
		if word == "--pre" || strings.HasPrefix(word, "--pre=") {
			return Prompt("")
		}
	}
	return Allow()
}

// validateSed requires the --sandbox flag to prevent execution or arbitrary file writes.
func validateSed(words []string) Decision {
	if !slices.Contains(words, "--sandbox") {
		return Prompt(SedSandboxAdvice)
	}
	return Allow()
}

// validateGit ensures git invocations only run permitted read-only subcommands.
func validateGit(words []string) Decision {
	if len(words) < 2 {
		return Prompt("")
	}
	if !allowedGitSubcommands[words[1]] {
		return Prompt("")
	}
	return Allow()
}
