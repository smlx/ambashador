package hook

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SedSandboxAdvice is context advice provided when sed is run without sandbox.
const SedSandboxAdvice = "Use 'sed --sandbox ...'"

// CommandValidator inspects arguments for a specific command and returns a Decision.
type CommandValidator func(args []string) Decision

// commandValidators registers specialized validation handlers for commands
// requiring deeper argument inspection.
var commandValidators = map[string]CommandValidator{
	"find":    validateFind,
	"git":     validateGit,
	"man":     validateMan,
	"nm":      validateNm,
	"objdump": validateObjdump,
	"rg":      validateRg,
	"sed":     validateSed,
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
	"diff":          true,
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
	"jq":            true,
	"ls":            true,
	"man":           true,
	"nl":            true,
	"nm":            true,
	"objdump":       true,
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

// disallowedGitGrepFlags identifies git grep arguments capable of arbitrary command execution.
var disallowedGitGrepFlags = map[string]bool{
	"--textconv": true,
}

// disallowedGitLogFlags identifies git log arguments capable of arbitrary command execution.
var disallowedGitLogFlags = map[string]bool{
	"--ext-diff": true,
	"--textconv": true,
}

// allowedManFlags defines safe flags permitted for man invocations.
var allowedManFlags = map[string]bool{
	"-a":                 true,
	"--all":              true,
	"-d":                 true,
	"--debug":            true,
	"-D":                 true,
	"--default":          true,
	"-f":                 true,
	"--whatis":           true,
	"-k":                 true,
	"--apropos":          true,
	"-K":                 true,
	"--global-apropos":   true,
	"-w":                 true,
	"--where":            true,
	"--path":             true,
	"--location":         true,
	"-W":                 true,
	"--where-cat":        true,
	"--location-cat":     true,
	"-i":                 true,
	"--ignore-case":      true,
	"-I":                 true,
	"--match-case":       true,
	"-u":                 true,
	"--update":           true,
	"--regex":            true,
	"--wildcard":         true,
	"--names-only":       true,
	"--no-subpages":      true,
	"--no-hyphenation":   true,
	"--nh":               true,
	"--no-justification": true,
	"--nj":               true,
	"-7":                 true,
	"--ascii":            true,
	"-?":                 true,
	"--help":             true,
	"--usage":            true,
	"-V":                 true,
	"--version":          true,
}

// allowedNmFlags defines safe flags permitted for nm invocations.
var allowedNmFlags = map[string]bool{
	"-a":                        true,
	"--debug-syms":              true,
	"-A":                        true,
	"--print-file-name":         true,
	"-B":                        true,
	"-C":                        true,
	"--demangle":                true,
	"--no-demangle":             true,
	"--recurse-limit":           true,
	"--no-recurse-limit":        true,
	"-D":                        true,
	"--dynamic":                 true,
	"-g":                        true,
	"--extern-only":             true,
	"-j":                        true,
	"--just-symbols":            true,
	"-l":                        true,
	"--line-numbers":            true,
	"-n":                        true,
	"--numeric-sort":            true,
	"-o":                        true,
	"-p":                        true,
	"--no-sort":                 true,
	"-P":                        true,
	"--portability":             true,
	"-r":                        true,
	"--reverse-sort":            true,
	"-S":                        true,
	"--print-size":              true,
	"-s":                        true,
	"--print-armap":             true,
	"--quiet":                   true,
	"--size-sort":               true,
	"--special-syms":            true,
	"--synthetic":               true,
	"-u":                        true,
	"--undefined-only":          true,
	"-U":                        true,
	"--defined-only":            true,
	"-W":                        true,
	"--no-weak":                 true,
	"--without-symbol-versions": true,
	"-h":                        true,
	"--help":                    true,
	"-V":                        true,
	"--version":                 true,
}

// allowedObjdumpFlags defines safe flags permitted for objdump invocations.
var allowedObjdumpFlags = map[string]bool{
	"-a":                   true,
	"--archive-headers":    true,
	"-f":                   true,
	"--file-headers":       true,
	"-p":                   true,
	"--private-headers":    true,
	"-h":                   true,
	"--section-headers":    true,
	"--headers":            true,
	"-x":                   true,
	"--all-headers":        true,
	"-d":                   true,
	"--disassemble":        true,
	"-D":                   true,
	"--disassemble-all":    true,
	"-S":                   true,
	"--source":             true,
	"-s":                   true,
	"--full-contents":      true,
	"-g":                   true,
	"--debugging":          true,
	"-e":                   true,
	"--debugging-tags":     true,
	"-G":                   true,
	"--stabs":              true,
	"-t":                   true,
	"--syms":               true,
	"-T":                   true,
	"--dynamic-syms":       true,
	"-r":                   true,
	"--reloc":              true,
	"-R":                   true,
	"--dynamic-reloc":      true,
	"-v":                   true,
	"--version":            true,
	"-i":                   true,
	"--info":               true,
	"-H":                   true,
	"--help":               true,
	"-l":                   true,
	"--line-numbers":       true,
	"-F":                   true,
	"--file-offsets":       true,
	"-C":                   true,
	"--demangle":           true,
	"--recurse-limit":      true,
	"--no-recurse-limit":   true,
	"-w":                   true,
	"--wide":               true,
	"-z":                   true,
	"--disassemble-zeroes": true,
	"--no-addresses":       true,
	"--prefix-addresses":   true,
	"--show-raw-insn":      true,
	"--no-show-raw-insn":   true,
	"--show-all-symbols":   true,
	"--special-syms":       true,
	"--inlines":            true,
}

// allowedGitSubcommands defines read-only git subcommands permitted for auto-approval.
var allowedGitSubcommands = map[string]bool{
	"diff":   true,
	"grep":   true,
	"show":   true,
	"status": true,
	"log":    true,
}

// allowedFilters defines commands permitted as downstream stages within a pipeline.
var allowedFilters = map[string]bool{
	"cat":  true,
	"cut":  true,
	"diff": true,
	"grep": true,
	"head": true,
	"jq":   true,
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

// extractLit validates that an unquoted literal string contains no escape characters.
func extractLit(v string) (string, bool) {
	if strings.Contains(v, `\`) {
		return "", false
	}
	return v, true
}

// unescapeDblQuotedLit unescapes literal content inside double quotes according
// to Bash rules: backslash only escapes $, `, ", \, and newline. For other
// characters, the backslash is preserved literally.
func unescapeDblQuotedLit(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			next := v[i+1]
			switch next {
			case '$', '`', '"', '\\':
				b.WriteByte(next)
				i++
			case '\n':
				// \<newline> is line continuation; omit both.
				i++
			default:
				b.WriteByte('\\')
			}
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
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
					b.WriteString(unescapeDblQuotedLit(d.Value))
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
	subcmd := words[1]
	if !allowedGitSubcommands[subcmd] {
		return Prompt("")
	}
	if subcmd == "grep" {
		return validateGitGrep(words[2:])
	}
	if subcmd == "log" {
		return validateGitLog(words[2:])
	}
	return Allow()
}

// validateGitLog verifies git log invocations do not execute external diff or text conversion drivers.
func validateGitLog(words []string) Decision {
	for _, word := range words {
		if disallowedGitLogFlags[word] {
			return Prompt("")
		}
	}
	return Allow()
}

// validateGitGrep verifies git grep invocations do not launch pagers or external converters.
func validateGitGrep(words []string) Decision {
	for _, word := range words {
		if disallowedGitGrepFlags[word] ||
			word == "-O" ||
			word == "--open-files-in-pager" ||
			strings.HasPrefix(word, "-O") ||
			strings.HasPrefix(word, "--open-files-in-pager=") {
			return Prompt("")
		}
	}
	return Allow()
}

// isSectionArg verifies if an argument matches a standard man section.
func isSectionArg(arg string) bool {
	if len(arg) == 0 || len(arg) > 3 {
		return false
	}
	first := arg[0]
	if first < '1' || first > '9' {
		return false
	}
	for i := 1; i < len(arg); i++ {
		ch := arg[i]
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') {
			return false
		}
	}
	return true
}

// validateMan verifies man arguments against an allowlist of flags, sections,
// and safe page names.
func validateMan(words []string) Decision {
	if len(words) < 2 {
		return Prompt("")
	}
	hasTarget := false
	for _, word := range words[1:] {
		if strings.HasPrefix(word, "-") {
			if !allowedManFlags[word] {
				return Prompt("")
			}
			continue
		}
		if isSectionArg(word) {
			continue
		}
		// Positional argument: ensure it does not start with special control characters
		// or contain file path separators that could reference local files.
		if strings.Contains(word, "/") || strings.Contains(word, `\`) {
			return Prompt("")
		}
		hasTarget = true
	}
	if !hasTarget {
		return Prompt("")
	}
	return Allow()
}

// validateNm verifies nm arguments against an allowlist of inspection flags.
func validateNm(words []string) Decision {
	for i := 1; i < len(words); i++ {
		word := words[i]
		if strings.HasPrefix(word, "@") {
			return Prompt("")
		}
		if !strings.HasPrefix(word, "-") {
			continue
		}
		if allowedNmFlags[word] {
			continue
		}
		switch {
		case strings.HasPrefix(word, "--format="):
			val := strings.TrimPrefix(word, "--format=")
			switch val {
			case "bsd", "sysv", "posix", "just-symbols":
			default:
				return Prompt("")
			}
		case word == "-f":
			if i+1 >= len(words) {
				return Prompt("")
			}
			i++
			switch words[i] {
			case "bsd", "sysv", "posix", "just-symbols":
			default:
				return Prompt("")
			}
		case strings.HasPrefix(word, "--radix="):
			val := strings.TrimPrefix(word, "--radix=")
			switch val {
			case "d", "o", "x":
			default:
				return Prompt("")
			}
		case word == "-t":
			if i+1 >= len(words) {
				return Prompt("")
			}
			i++
			switch words[i] {
			case "d", "o", "x":
			default:
				return Prompt("")
			}
		case strings.HasPrefix(word, "--demangle="):
			val := strings.TrimPrefix(word, "--demangle=")
			switch val {
			case "none", "auto", "gnu-v3", "java", "gnat", "dlang", "rust":
			default:
				return Prompt("")
			}
		case word == "-C":
			// Handled in allowedNmFlags
		default:
			return Prompt("")
		}
	}
	return Allow()
}

// validateObjdump verifies objdump arguments against an allowlist of inspection flags.
func validateObjdump(words []string) Decision {
	for i := 1; i < len(words); i++ {
		word := words[i]
		if strings.HasPrefix(word, "@") {
			return Prompt("")
		}
		if !strings.HasPrefix(word, "-") {
			continue
		}
		if allowedObjdumpFlags[word] {
			continue
		}
		switch {
		case strings.HasPrefix(word, "-j"), strings.HasPrefix(word, "--section="):
			// safe section name specification
		case word == "--section":
			if i+1 >= len(words) {
				return Prompt("")
			}
			i++
		case strings.HasPrefix(word, "-M"), strings.HasPrefix(word, "--disassembler-options="):
			// safe disassembler options
		case word == "--disassembler-options":
			if i+1 >= len(words) {
				return Prompt("")
			}
			i++
		case strings.HasPrefix(word, "--disassemble="):
			// safe symbol disassembly filter
		case strings.HasPrefix(word, "--demangle="):
			val := strings.TrimPrefix(word, "--demangle=")
			switch val {
			case "none", "auto", "gnu-v3", "java", "gnat", "dlang", "rust":
			default:
				return Prompt("")
			}
		case strings.HasPrefix(word, "--insn-width="):
			// safe numeric formatting option
		case strings.HasPrefix(word, "--start-address="), strings.HasPrefix(word, "--stop-address="):
			// safe address bounds
		case strings.HasPrefix(word, "--adjust-vma="):
			// safe offset adjustment
		default:
			return Prompt("")
		}
	}
	return Allow()
}
