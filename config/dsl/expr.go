// Package dsl implements a small rule expression language that can be used
// to compose detection conditions that are not expressible with a single
// TOML rule, e.g. combining multiple regexes, entropy thresholds, and path
// allow/deny lists with boolean logic.
//
// Grammar (operators are case-insensitive):
//
//	expr      := orExpr
//	orExpr    := andExpr ( ("or" | "||") andExpr )*
//	andExpr   := unary ( ("and" | "&&") unary )*
//	unary     := ("not" | "!") unary | "(" expr ")" | predicate
//	predicate := "match" "(" string ("," integer)? ")"   // content regex, optional secret group
//	           | "path" "(" string ")"                   // file path regex
//	           | "entropy" (">"|">="|"<"|"<="|"=="|"!=") number
//
// The first match() term that is not negated by 'not' is the primary
// pattern: only its matches are reported as findings. All other terms act
// as conditions on those findings.
//
// Example:
//
//	match("AKIA[0-9A-Z]{16}") and entropy >= 3.5 and not path("testdata/")
package dsl

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// Context carries the state an expression is evaluated against. Content and
// the paths are fragment-scoped, Entropy is scoped to the candidate finding.
type Context struct {
	// Content is the raw text of the fragment being scanned.
	Content string

	// FilePath is the path of the file being scanned.
	FilePath string

	// WindowsFilePath is the Windows-style path of the file, if any.
	WindowsFilePath string

	// Entropy is the shannon entropy of the candidate secret.
	Entropy float64
}

// Node is a single node in a parsed expression tree.
type Node interface {
	// Eval evaluates the node against the given context.
	Eval(ctx *Context) bool

	// String returns a human-readable representation of the node.
	String() string
}

// And is true when both operands are true.
type And struct {
	Left, Right Node
}

func (n *And) Eval(ctx *Context) bool { return n.Left.Eval(ctx) && n.Right.Eval(ctx) }
func (n *And) String() string         { return fmt.Sprintf("(%s and %s)", n.Left, n.Right) }

// Or is true when at least one operand is true.
type Or struct {
	Left, Right Node
}

func (n *Or) Eval(ctx *Context) bool { return n.Left.Eval(ctx) || n.Right.Eval(ctx) }
func (n *Or) String() string         { return fmt.Sprintf("(%s or %s)", n.Left, n.Right) }

// Not negates its operand.
type Not struct {
	Operand Node
}

func (n *Not) Eval(ctx *Context) bool { return !n.Operand.Eval(ctx) }
func (n *Not) String() string         { return fmt.Sprintf("not %s", n.Operand) }

// Match is a content regex predicate. It is true when the regex matches
// anywhere in the fragment content. Match terms also act as candidate
// generators: every regex match in the content produces a candidate finding.
type Match struct {
	// Regex is the content regular expression.
	Regex *regexp.Regexp

	// Group is the capture group used to extract the secret from a match.
	// Zero means the whole match (or the first non-empty capture group).
	Group int

	raw string
}

func (m *Match) Eval(ctx *Context) bool { return m.Regex.MatchString(ctx.Content) }
func (m *Match) String() string {
	if m.Group > 0 {
		return fmt.Sprintf("match(%q, %d)", m.raw, m.Group)
	}
	return fmt.Sprintf("match(%q)", m.raw)
}

// Path is a file path predicate. It is true when the regex matches the path
// of the file being scanned.
type Path struct {
	Regex *regexp.Regexp

	raw string
}

func (p *Path) Eval(ctx *Context) bool {
	if p.Regex.MatchString(ctx.FilePath) {
		return true
	}
	return ctx.WindowsFilePath != "" && p.Regex.MatchString(ctx.WindowsFilePath)
}
func (p *Path) String() string { return fmt.Sprintf("path(%q)", p.raw) }

// Entropy compares the entropy of the candidate secret against a threshold.
type Entropy struct {
	// Op is one of: >, >=, <, <=, ==, !=
	Op string

	// Value is the threshold the candidate entropy is compared against.
	Value float64
}

func (e *Entropy) Eval(ctx *Context) bool {
	switch e.Op {
	case ">":
		return ctx.Entropy > e.Value
	case ">=":
		return ctx.Entropy >= e.Value
	case "<":
		return ctx.Entropy < e.Value
	case "<=":
		return ctx.Entropy <= e.Value
	case "==":
		return ctx.Entropy == e.Value
	case "!=":
		return ctx.Entropy != e.Value
	}
	return false
}
func (e *Entropy) String() string { return fmt.Sprintf("entropy %s %g", e.Op, e.Value) }

// Expr is a parsed and validated DSL expression.
type Expr struct {
	root Node

	// primary is the first match() term that is not negated by 'not'. Only
	// its matches are reported as findings.
	primary *Match

	// matches contains the unique match terms of the expression, in order of
	// appearance.
	matches []*Match

	source string
}

// Parse parses and validates a DSL expression. An expression must contain at
// least one positive (non-negated) match() term, otherwise it could never
// produce a finding.
func Parse(source string) (*Expr, error) {
	if strings.TrimSpace(source) == "" {
		return nil, fmt.Errorf("expression is empty")
	}

	tokens, err := lex(source)
	if err != nil {
		return nil, err
	}

	p := &parser{tokens: tokens}
	root, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokenEOF {
		return nil, fmt.Errorf("unexpected %s after end of expression", p.peek())
	}

	expr := &Expr{root: root, source: source}
	seen := make(map[string]struct{})
	collectMatches(root, false, seen, expr)
	if expr.primary == nil {
		return nil, fmt.Errorf("expression must contain at least one positive match() term (a match() that is not negated by 'not')")
	}
	return expr, nil
}

// Eval evaluates the expression against the given context.
func (e *Expr) Eval(ctx *Context) bool {
	return e.root.Eval(ctx)
}

// Primary returns the primary match() term of the expression: the first
// match() term that is not negated by 'not'. Only matches of this term are
// reported as findings.
func (e *Expr) Primary() *Match {
	return e.primary
}

// MatchTerms returns the unique match() terms of the expression, in order of
// appearance.
func (e *Expr) MatchTerms() []*Match {
	return e.matches
}

// String returns the normalized representation of the expression.
func (e *Expr) String() string {
	return e.root.String()
}

func collectMatches(n Node, negated bool, seen map[string]struct{}, expr *Expr) {
	switch node := n.(type) {
	case *Match:
		key := fmt.Sprintf("%s\x00%d", node.raw, node.Group)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			expr.matches = append(expr.matches, node)
		}
		if !negated && expr.primary == nil {
			expr.primary = node
		}
	case *And:
		collectMatches(node.Left, negated, seen, expr)
		collectMatches(node.Right, negated, seen, expr)
	case *Or:
		collectMatches(node.Left, negated, seen, expr)
		collectMatches(node.Right, negated, seen, expr)
	case *Not:
		collectMatches(node.Operand, !negated, seen, expr)
	}
}
