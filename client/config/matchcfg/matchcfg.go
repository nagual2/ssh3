// Package matchcfg resolves SSH client configuration with support for the
// Match directive.
//
// github.com/kevinburke/ssh_config v1.2.0 (the parser used by ssh3) rejects
// the Match keyword both at parse time and at lookup time, so a config file
// containing a Match block currently aborts the client. This package adds a
// thin Match-aware layer on top of it: the raw config text is split into
// Host/Match sections, the Match blocks are evaluated for one specific host
// alias, the blocks that apply are rewritten into plain "Host *" sections and
// the result is handed back to ssh_config for regular Get/GetAll lookups.
// Because the rewritten text keeps the document order, the ssh_config "first
// obtained value wins" rule yields the same priorities as OpenSSH.
//
// Supported Match criteria: all, final, canonical, host, originalhost, user,
// localuser and exec, with negated ("!") comma-separated glob patterns where
// a pattern list is expected. The semantics follow ssh_config(5) with two
// ssh3-specific simplifications:
//
//   - ssh3 never canonicalizes hostnames, so the configuration is applied in
//     a single pass; that pass is the final one ("final" always matches,
//     "canonical" never does). This mirrors ssh(1) with
//     CanonicalizeHostname=no, where OpenSSH re-parses the config with the
//     final flag and re-derives every value with first-wins semantics, which
//     is equivalent to applying final blocks in document order.
//   - "host" and "user" criteria are evaluated against the evolving target
//     host/user: once a matching section sets HostName or User, later Match
//     blocks see the updated values, mirroring the way OpenSSH updates its
//     connection info while parsing.
//
// exec runs the command with "sh -c" (unix) or "cmd /c" (windows) and matches
// on exit status 0; OpenSSH uses the user's login shell instead.
//
// Include is handled here too: the content of an included file is spliced into
// the configuration at the place of the directive before anything else is
// parsed, exactly like OpenSSH. This is what makes Host and Match blocks of an
// included file participate in the alias and Match filtering instead of being
// handled (or rejected) by the ssh_config parser.
package matchcfg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kevinburke/ssh_config"
)

type sectionKind int

const (
	// sectionTop holds directives written before any Host/Match line; the
	// ssh_config parser attaches them to an implicit "Host *" block that
	// always applies.
	sectionTop sectionKind = iota
	sectionHost
	sectionMatch
)

type criterionKind int

const (
	criterionAll criterionKind = iota
	criterionCanonical
	criterionFinal
	criterionHost
	criterionOriginalHost
	criterionUser
	criterionLocalUser
	criterionExec
)

// criterion is a single Match attribute with its argument (if any).
type criterion struct {
	kind     criterionKind
	negate   bool                  // '!' prefix on the attribute itself
	patterns []*ssh_config.Pattern // for host, originalhost, user and localuser
	command  string                // for exec
}

// section is one block of the config file: either the directives written
// before the first Host/Match line, or a Host/Match line plus everything up
// to the next Host/Match line.
type section struct {
	kind        sectionKind
	line        int                   // 1-based line number of the header, 0 for sectionTop
	header      string                // verbatim header line (sectionHost only)
	patterns    []*ssh_config.Pattern // compiled Host patterns (sectionHost)
	patternsErr error                 // Host pattern compilation error, if any
	criteria    []criterion           // parsed criteria (sectionMatch)
	body        []string              // verbatim body lines
}

// configLine is one physical line of the configuration together with the file
// it comes from, so that parse errors keep pointing at the file that really
// holds the offending line once Include has spliced files together.
type configLine struct {
	text string
	file string
	num  int // 1-based line number inside file
}

// pos renders the origin of the line the way an editor expects it, so that a
// parse error points at the included file rather than at the main config.
func (l configLine) pos() string {
	if l.file == "" {
		return fmt.Sprintf("line %d", l.num)
	}
	return fmt.Sprintf("%s:%d", l.file, l.num)
}

// maxIncludeDepth bounds the recursion of Include directives. OpenSSH refuses
// to parse more than five nested levels; ssh3 uses a larger bound and stops
// expanding at the limit instead of failing, so that a pathological
// configuration can never block a connection.
const maxIncludeDepth = 16

// Resolver resolves one SSH config file (typically ~/.ssh/config) for a given
// host alias, with support for Match blocks. After a successful New, a
// Resolver is read-only and safe for concurrent use.
type Resolver struct {
	userConfigPath  string
	userConfigBytes []byte
	sections        []section
	hasMatch        bool
	localUser       string
	execRunner      func(command string) bool
}

// New builds a Resolver from the raw content of a user SSH config file. The
// file structure and every Match criterion are parsed eagerly, so syntax
// errors (including invalid Match criteria) are reported before any
// connection is attempted. Include directives are expanded first, so their
// errors point at the included file.
func New(userConfigPath string, userConfigBytes []byte) (*Resolver, error) {
	r := &Resolver{
		userConfigPath:  userConfigPath,
		userConfigBytes: userConfigBytes,
		execRunner:      defaultExecRunner,
	}
	if u, err := osuser.Current(); err == nil {
		r.localUser = u.Username
	}
	lines, expanded, err := expandIncludes(userConfigPath, userConfigBytes)
	if err != nil {
		return nil, err
	}
	if expanded {
		r.userConfigBytes = joinLines(lines)
	}
	sections, hasMatch, err := parseSections(lines)
	if err != nil {
		return nil, err
	}
	r.sections = sections
	r.hasMatch = hasMatch
	return r, nil
}

// ConfigForHost returns the configuration resolved for alias. The user
// argument is the username known before reading the config (command line or
// URL); when empty, the local OS user is assumed, as ssh(1) does. Configs
// without any Match block are returned exactly as ssh_config.DecodeBytes
// would parse them, byte for byte. A nil Resolver resolves to a nil config.
func (r *Resolver) ConfigForHost(alias string, user string) (*ssh_config.Config, error) {
	if r == nil {
		return nil, nil
	}
	if !r.hasMatch {
		// Fast path: no Match block, parse the config as-is.
		return ssh_config.DecodeBytes(r.userConfigBytes)
	}
	filtered, err := r.filter(alias, user)
	if err != nil {
		return nil, err
	}
	return ssh_config.DecodeBytes(filtered)
}

// filter rewrites the config for one alias: every section whose Match
// criteria all apply is kept as a synthetic "Host *" block, other Match
// sections are dropped, Host sections and leading directives are kept
// verbatim.
func (r *Resolver) filter(alias string, cliUser string) ([]byte, error) {
	effectiveHost := alias
	// OpenSSH computes the Match user value as options->user when set (CLI
	// user, which a config User directive cannot override), falling back to
	// the local user until the first active User directive provides one.
	userSeen := cliUser != "" // a User value has already been obtained
	effectiveUser := cliUser
	if effectiveUser == "" {
		effectiveUser = r.localUser
	}
	hostSeen := false // a HostName value has already been obtained (first wins)

	var buf bytes.Buffer
	for i := range r.sections {
		sec := &r.sections[i]
		switch sec.kind {
		case sectionTop:
			// Leading directives always apply (implicit "Host *" block).
			writeBody(&buf, sec)
			updateMatchState(sec.body, &effectiveHost, &hostSeen, &effectiveUser, &userSeen)
		case sectionHost:
			if sec.patternsErr != nil {
				return nil, sec.patternsErr
			}
			// Host sections are kept verbatim: the ssh_config parser applies
			// its own alias filtering on them.
			buf.WriteString(sec.header)
			buf.WriteByte('\n')
			writeBody(&buf, sec)
			if matchPatternList(sec.patterns, alias) {
				updateMatchState(sec.body, &effectiveHost, &hostSeen, &effectiveUser, &userSeen)
			}
		case sectionMatch:
			if r.matchSection(sec, alias, effectiveHost, effectiveUser) {
				// A matching Match block applies to the connection regardless
				// of the alias; rewriting it as "Host *" keeps the document
				// order, hence the OpenSSH priorities.
				buf.WriteString("Host *\n")
				writeBody(&buf, sec)
				updateMatchState(sec.body, &effectiveHost, &hostSeen, &effectiveUser, &userSeen)
			}
		}
	}
	return buf.Bytes(), nil
}

// Get resolves the first value of key for alias, with Match blocks applied.
// It is the Match-aware equivalent of ssh_config.Config.Get. Because no
// explicit user is known at this level, the local user is assumed for the
// Match user criterion, exactly like ssh(1) invoked without a user argument.
func (r *Resolver) Get(alias, key string) (string, error) {
	cfg, err := r.ConfigForHost(alias, "")
	if err != nil || cfg == nil {
		return "", err
	}
	return cfg.Get(alias, key)
}

// GetAll resolves every value of key for alias, with Match blocks applied.
// It is the Match-aware equivalent of ssh_config.Config.GetAll. See Get for
// the user assumption.
func (r *Resolver) GetAll(alias, key string) ([]string, error) {
	cfg, err := r.ConfigForHost(alias, "")
	if err != nil || cfg == nil {
		return nil, err
	}
	return cfg.GetAll(alias, key)
}

// matchSection reports whether every criterion of a Match block applies,
// mirroring the OpenSSH loop: each criterion is evaluated to a boolean and
// then inverted if the attribute was negated with '!'. Evaluation stops at
// the first failing criterion, so exec commands after a failed predicate are
// never run.
func (r *Resolver) matchSection(sec *section, alias, effectiveHost, effectiveUser string) bool {
	for i := range sec.criteria {
		c := &sec.criteria[i]
		var raw bool
		switch c.kind {
		case criterionAll:
			raw = true
		case criterionFinal:
			// ssh3 parses the config in a single pass and never canonicalizes
			// hostnames, so that pass is the final one.
			raw = true
		case criterionCanonical:
			// ssh3 never canonicalizes hostnames.
			raw = false
		case criterionHost:
			raw = matchPatternList(c.patterns, effectiveHost)
		case criterionOriginalHost:
			raw = matchPatternList(c.patterns, alias)
		case criterionUser:
			raw = matchPatternList(c.patterns, effectiveUser)
		case criterionLocalUser:
			raw = matchPatternList(c.patterns, r.localUser)
		case criterionExec:
			raw = r.execRunner(c.command)
		}
		if raw == c.negate {
			return false
		}
	}
	return true
}

// parseSections splits a config text into sections. Only Match criteria are
// validated here; everything else is kept verbatim for the ssh_config parser,
// which stays the single source of truth for directive syntax.
func parseSections(lines []configLine) (sections []section, hasMatch bool, err error) {
	var ptrs []*section
	var cur *section
	for i := range lines {
		raw := lines[i].text
		trimmed := strings.TrimLeft(raw, " \t")
		keyword, rest := splitKey(trimmed)
		switch strings.ToLower(keyword) {
		case "host":
			sec := &section{kind: sectionHost, line: lines[i].num, header: raw}
			sec.patterns, sec.patternsErr = parseHostPatterns(rest, lines[i])
			ptrs = append(ptrs, sec)
			cur = sec
			continue
		case "match":
			sec := &section{kind: sectionMatch, line: lines[i].num}
			sec.criteria, err = parseMatchCriteria(rest, lines[i])
			if err != nil {
				return nil, false, err
			}
			hasMatch = true
			ptrs = append(ptrs, sec)
			cur = sec
			continue
		}
		if cur == nil {
			// Directives before the first Host/Match line belong to the
			// implicit "Host *" block.
			cur = &section{kind: sectionTop}
			ptrs = append(ptrs, cur)
		}
		cur.body = append(cur.body, raw)
	}
	sections = make([]section, len(ptrs))
	for i, p := range ptrs {
		sections[i] = *p
	}
	return sections, hasMatch, nil
}

// expandIncludes returns the lines of the configuration with every Include
// directive replaced by the lines of the files it matches, exactly like
// OpenSSH: the content of an included file takes the place of the directive
// and therefore continues the Host or Match block that surrounds it. expanded
// reports whether at least one Include directive was expanded.
func expandIncludes(path string, content []byte) (lines []configLine, expanded bool, err error) {
	return expandIncludeLines(newLines(path, content), 0, make(map[string]bool))
}

// newLines splits raw file content into located configuration lines.
func newLines(path string, content []byte) []configLine {
	raw := strings.Split(string(content), "\n")
	lines := make([]configLine, len(raw))
	for i, text := range raw {
		lines[i] = configLine{text: text, file: path, num: i + 1}
	}
	return lines
}

// joinLines renders located lines back into a config text.
func joinLines(lines []configLine) []byte {
	var buf bytes.Buffer
	for i := range lines {
		buf.WriteString(lines[i].text)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// expandIncludeLines recursively expands the Include directives of lines.
// stack holds the canonical paths of the files currently being expanded and is
// the loop guard for cyclic includes.
func expandIncludeLines(lines []configLine, depth int, stack map[string]bool) ([]configLine, bool, error) {
	out := make([]configLine, 0, len(lines))
	expanded := false
	for i := range lines {
		targets, ok := includeTargets(lines[i])
		if !ok {
			out = append(out, lines[i])
			continue
		}
		expanded = true
		if depth >= maxIncludeDepth {
			continue
		}
		included, err := expandIncludeTargets(targets, lines[i], depth, stack)
		if err != nil {
			return nil, false, err
		}
		out = append(out, included...)
	}
	return out, expanded, nil
}

// includeTargets reports whether line is an Include directive and returns the
// file patterns it lists. An Include without arguments yields no target, which
// ssh(1) also ignores.
func includeTargets(line configLine) (targets []string, ok bool) {
	keyword, rest := splitKey(strings.TrimLeft(line.text, " \t"))
	if !strings.EqualFold(keyword, "include") {
		return nil, false
	}
	return strings.Fields(normalizeValue(rest)), true
}

// expandIncludeTargets expands one Include directive: every listed pattern is
// globbed, the matched files are read and expanded recursively in glob order,
// and each file contributes at most once per directive.
func expandIncludeTargets(targets []string, directive configLine, depth int, stack map[string]bool) ([]configLine, error) {
	var out []configLine
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		matches, err := globInclude(target, directive.file)
		if err != nil {
			return nil, fmt.Errorf("%s: Include %s: %v", directive.pos(), target, err)
		}
		for _, match := range matches {
			key, err := filepath.Abs(match)
			if err != nil {
				key = match
			}
			if seen[key] || stack[key] {
				// Already pulled in by this directive, or a cyclic include:
				// OpenSSH aborts on the latter, ssh3 stops expanding.
				continue
			}
			seen[key] = true
			content, err := os.ReadFile(match)
			if err != nil {
				// An unreadable include must not invalidate the rest of the
				// configuration; OpenSSH only warns about it.
				continue
			}
			stack[key] = true
			expanded, _, err := expandIncludeLines(newLines(match, content), depth+1, stack)
			delete(stack, key)
			if err != nil {
				return nil, err
			}
			out = append(out, expanded...)
		}
	}
	return out, nil
}

// globInclude expands one Include target into the files it matches. An
// absolute path (or a "~"-prefixed one) is used as is; a relative path is
// first resolved against the directory of the including file and then against
// ~/.ssh, which is where OpenSSH anchors relative Include paths. A pattern
// matching nothing is not an error, exactly as with ssh(1).
func globInclude(target, includingFile string) ([]string, error) {
	resolved := target
	if home := userHomeDir(); home != "" && (target == "~" || strings.HasPrefix(target, "~/") || strings.HasPrefix(target, `~\`)) {
		resolved = filepath.Join(home, strings.TrimLeft(target[1:], `/\`))
	}
	if !filepath.IsAbs(resolved) {
		candidates := []string{filepath.Join(filepath.Dir(includingFile), resolved)}
		if sshDir := userSSHDir(); sshDir != "" {
			candidates = append(candidates, filepath.Join(sshDir, resolved))
		}
		for _, candidate := range candidates {
			matches, err := filepath.Glob(candidate)
			if err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				return matches, nil
			}
		}
		return nil, nil
	}
	return filepath.Glob(resolved)
}

// userSSHDir returns the ~/.ssh directory, where OpenSSH anchors relative
// Include paths. It returns "" when the home directory is unknown.
func userSSHDir() string {
	if home := userHomeDir(); home != "" {
		return filepath.Join(home, ".ssh")
	}
	return ""
}

// userHomeDir returns the home directory of the current user, preferring the
// one reported by os/user and falling back to the environment (the os/user
// lookup can fail in statically linked or cross-compiled builds).
func userHomeDir() string {
	if u, err := osuser.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	for _, key := range []string{"HOME", "USERPROFILE"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

// splitKey splits the first whitespace- or '='-delimited token from line and
// returns it with the remainder (the ssh_config lexer accepts "key value",
// "key=value" and "key = value" forms).
func splitKey(line string) (key, rest string) {
	if idx := strings.IndexAny(line, " \t="); idx >= 0 {
		return line[:idx], line[idx:]
	}
	return line, ""
}

// normalizeValue applies the value lexing rules of the ssh_config parser to
// the text following a keyword: an optional '=', leading spaces removed and
// the value terminated by an end-of-line comment or a carriage return.
func normalizeValue(rest string) string {
	rest = strings.TrimLeft(rest, " \t")
	rest = strings.TrimPrefix(rest, "=")
	rest = strings.TrimLeft(rest, " \t")
	rest = strings.TrimRight(rest, "\r")
	if cut := strings.Index(rest, "#"); cut >= 0 {
		rest = rest[:cut]
	}
	return rest
}

// parseHostPatterns extracts the patterns of a Host line, using the same
// syntax as the ssh_config parser (glob wildcards, '!' negation).
func parseHostPatterns(rest string, line configLine) ([]*ssh_config.Pattern, error) {
	strs := strings.Fields(normalizeValue(rest))
	patterns := make([]*ssh_config.Pattern, 0, len(strs))
	for _, s := range strs {
		p, err := ssh_config.NewPattern(s)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid host pattern %q: %v", line.pos(), s, err)
		}
		patterns = append(patterns, p)
	}
	return patterns, nil
}

// parseMatchCriteria parses the argument list of a Match line. Unknown
// criteria are rejected so that a typo never silently changes which blocks
// apply. Like OpenSSH, an attribute may be negated with a leading '!' and a
// value criterion accepts an "attr=value" form.
func parseMatchCriteria(rest string, line configLine) ([]criterion, error) {
	args, err := splitMatchArgs(normalizeValue(rest))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", line.pos(), err)
	}
	var criteria []criterion
	for i := 0; i < len(args); i++ {
		token := args[i]
		negate := false
		if strings.HasPrefix(token, "!") {
			negate = true
			token = token[1:]
		}
		// "attr=value" form: the argument is part of the attribute token.
		inlineValue := ""
		hasInlineValue := false
		if eq := strings.Index(token, "="); eq >= 0 {
			hasInlineValue = true
			inlineValue = token[eq+1:]
			token = token[:eq]
		}
		attr := strings.ToLower(token)
		// value returns the argument of a value-taking criterion, consuming
		// the next token unless the "attr=value" form was used.
		value := func() (string, error) {
			switch {
			case hasInlineValue:
				return inlineValue, nil
			case i+1 < len(args):
				i++
				return args[i], nil
			default:
				return "", fmt.Errorf("%s: Match criterion %q requires a value", line.pos(), attr)
			}
		}
		switch attr {
		case "all", "final", "canonical":
			if hasInlineValue {
				return nil, fmt.Errorf("%s: unsupported Match criterion %q", line.pos(), args[i])
			}
			kind := criterionAll
			switch attr {
			case "final":
				kind = criterionFinal
			case "canonical":
				kind = criterionCanonical
			}
			criteria = append(criteria, criterion{kind: kind, negate: negate})
		case "host", "originalhost", "user", "localuser":
			arg, err := value()
			if err != nil {
				return nil, err
			}
			patterns, err := parsePatternList(arg)
			if err != nil {
				return nil, fmt.Errorf("%s: Match %s: %v", line.pos(), attr, err)
			}
			kind := criterionHost
			switch attr {
			case "originalhost":
				kind = criterionOriginalHost
			case "user":
				kind = criterionUser
			case "localuser":
				kind = criterionLocalUser
			}
			criteria = append(criteria, criterion{kind: kind, negate: negate, patterns: patterns})
		case "exec":
			arg, err := value()
			if err != nil {
				return nil, err
			}
			criteria = append(criteria, criterion{kind: criterionExec, negate: negate, command: arg})
		default:
			return nil, fmt.Errorf("%s: unsupported Match criterion %q", line.pos(), args[i])
		}
	}
	if len(criteria) == 0 {
		return nil, fmt.Errorf("%s: Match directive without criteria", line.pos())
	}
	for i := range criteria {
		if criteria[i].kind == criterionAll && len(criteria) > 1 {
			return nil, fmt.Errorf("%s: Match \"all\" cannot be combined with other Match attributes", line.pos())
		}
	}
	return criteria, nil
}

// splitMatchArgs splits a Match argument list into whitespace-separated
// tokens. Double quotes group several words into a single argument (mainly
// for exec commands); a '#' outside quotes starts an end-of-line comment,
// consistently with the rest of the file as lexed by ssh_config.
func splitMatchArgs(rest string) ([]string, error) {
	var args []string
	var token strings.Builder
	inToken := false
	inQuotes := false
	for _, r := range rest {
		switch {
		case inQuotes:
			if r == '"' {
				inQuotes = false
			} else {
				token.WriteRune(r)
			}
		case r == '"':
			inQuotes = true
			inToken = true
		case r == ' ' || r == '\t' || r == '\r':
			if inToken {
				args = append(args, token.String())
				token.Reset()
				inToken = false
			}
		case r == '#':
			// End-of-line comment: discard the rest of the line.
			if inToken {
				args = append(args, token.String())
			}
			return args, nil
		default:
			token.WriteRune(r)
			inToken = true
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("unterminated quoted argument")
	}
	if inToken {
		args = append(args, token.String())
	}
	return args, nil
}

// parsePatternList compiles a comma-separated pattern list with the same
// syntax as Host patterns: glob wildcards (* and ?) and a leading '!' for
// negated entries.
func parsePatternList(value string) ([]*ssh_config.Pattern, error) {
	var patterns []*ssh_config.Pattern
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		p, err := ssh_config.NewPattern(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %v", entry, err)
		}
		patterns = append(patterns, p)
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("empty pattern list")
	}
	return patterns, nil
}

// matchPatternList reports whether value matches a pattern list, with the
// exact semantics of ssh_config.Host.Matches: at least one positive pattern
// must match, and any matching negated pattern rejects the whole list.
func matchPatternList(patterns []*ssh_config.Pattern, value string) bool {
	return (&ssh_config.Host{Patterns: patterns}).Matches(value)
}

// updateMatchState implements the OpenSSH rule that Match host/user criteria
// see the HostName/User values obtained so far: the first obtained value wins
// and is used by every later block.
func updateMatchState(body []string, effectiveHost *string, hostSeen *bool, effectiveUser *string, userSeen *bool) {
	if !*hostSeen {
		if v, ok := firstDirective(body, "hostname"); ok {
			*effectiveHost = v
			*hostSeen = true
		}
	}
	if !*userSeen {
		if v, ok := firstDirective(body, "user"); ok {
			*effectiveUser = v
			*userSeen = true
		}
	}
}

// firstDirective returns the value of the first directive with the given key
// in a section body, following the value lexing rules of the ssh_config
// parser. ok is false when the key does not appear or has an empty value.
func firstDirective(body []string, key string) (value string, ok bool) {
	for _, raw := range body {
		line := strings.TrimLeft(raw, " \t")
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, rest := splitKey(line)
		if !strings.EqualFold(k, key) {
			continue
		}
		v := normalizeValue(rest)
		v = strings.TrimRight(v, " \t")
		if v == "" {
			return "", false
		}
		return v, true
	}
	return "", false
}

// writeBody copies the verbatim lines of a section body to buf.
func writeBody(buf *bytes.Buffer, sec *section) {
	for _, line := range sec.body {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
}

// defaultExecRunner executes an exec criterion command and reports whether it
// exited with status 0. OpenSSH runs the command with the user's login shell;
// ssh3 uses sh -c (unix) or cmd /c (windows).
func defaultExecRunner(command string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}
