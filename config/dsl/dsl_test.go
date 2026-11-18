package dsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantErr bool
	}{
		{name: "single match", source: `match("AKIA[0-9A-Z]{16}")`},
		{name: "match with group", source: `match("api[_-]?key\s*=\s*'([0-9a-zA-Z-]{36})'", 1)`},
		{name: "and combination", source: `match("a") and match("b")`},
		{name: "or combination", source: `match("a") or match("b")`},
		{name: "symbol operators", source: `match("a") && (match("b") || match("c"))`},
		{name: "not path", source: `match("a") and not path("testdata/")`},
		{name: "bang negation", source: `match("a") and !path("testdata/")`},
		{name: "entropy threshold", source: `match("a") and entropy >= 3.5`},
		{name: "entropy all ops", source: `match("a") and (entropy > 1 or entropy < 5 or entropy == 3 or entropy != 2 or entropy <= 4)`},
		{name: "case insensitive keywords", source: `MATCH("a") AND NOT PATH("x")`},
		{name: "nested parens", source: `(match("a") and (match("b") or match("c"))) and not (path("x") or path("y"))`},
		{name: "escaped string", source: `match("a\"b\\\\d+")`},

		{name: "empty expression", source: ``, wantErr: true},
		{name: "whitespace only", source: `   `, wantErr: true},
		{name: "no match term", source: `path("x") and entropy > 3`, wantErr: true},
		{name: "only negated match term", source: `not match("a")`, wantErr: true},
		{name: "unbalanced paren", source: `(match("a")`, wantErr: true},
		{name: "trailing operator", source: `match("a") and`, wantErr: true},
		{name: "leading operator", source: `and match("a")`, wantErr: true},
		{name: "unknown function", source: `foo("a")`, wantErr: true},
		{name: "match without parens", source: `match "a"`, wantErr: true},
		{name: "match without args", source: `match()`, wantErr: true},
		{name: "match bad regex", source: `match("a[")`, wantErr: true},
		{name: "path bad regex", source: `match("a") and path("b[")`, wantErr: true},
		{name: "group out of range", source: `match("(a)", 2)`, wantErr: true},
		{name: "negative group", source: `match("(a)", -1)`, wantErr: true},
		{name: "entropy missing op", source: `match("a") and entropy 3.5`, wantErr: true},
		{name: "entropy missing value", source: `match("a") and entropy >=`, wantErr: true},
		{name: "entropy negative value", source: `match("a") and entropy >= -1`, wantErr: true},
		{name: "single ampersand", source: `match("a") & match("b")`, wantErr: true},
		{name: "single pipe", source: `match("a") | match("b")`, wantErr: true},
		{name: "single equals", source: `match("a") and entropy = 3`, wantErr: true},
		{name: "unterminated string", source: `match("a`, wantErr: true},
		{name: "unexpected token after expression", source: `match("a") "b"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.source)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, expr.MatchTerms())
		})
	}
}

func TestEval(t *testing.T) {
	tests := []struct {
		name   string
		source string
		ctx    *Context
		want   bool
	}{
		{
			name:   "match hit",
			source: `match("AKIA[0-9A-Z]{16}")`,
			ctx:    &Context{Content: "key = AKIAIOSFODNN7EXAMPLE"},
			want:   true,
		},
		{
			name:   "match miss",
			source: `match("AKIA[0-9A-Z]{16}")`,
			ctx:    &Context{Content: "nothing here"},
			want:   false,
		},
		{
			name:   "and combination both present",
			source: `match("aws") and match("[0-9a-f]{32}")`,
			ctx:    &Context{Content: "aws token: 0123456789abcdef0123456789abcdef"},
			want:   true,
		},
		{
			name:   "and combination one missing",
			source: `match("aws") and match("[0-9a-f]{32}")`,
			ctx:    &Context{Content: "aws token: not-hex"},
			want:   false,
		},
		{
			name:   "or combination",
			source: `match("aws") or match("gcp")`,
			ctx:    &Context{Content: "gcp key"},
			want:   true,
		},
		{
			name:   "entropy above threshold",
			source: `match("a") and entropy >= 3.5`,
			ctx:    &Context{Content: "a", Entropy: 4.0},
			want:   true,
		},
		{
			name:   "entropy below threshold",
			source: `match("a") and entropy >= 3.5`,
			ctx:    &Context{Content: "a", Entropy: 3.0},
			want:   false,
		},
		{
			name:   "path allowlist excludes",
			source: `match("a") and not path("testdata/")`,
			ctx:    &Context{Content: "a", FilePath: "testdata/secret.txt"},
			want:   false,
		},
		{
			name:   "path allowlist passes",
			source: `match("a") and not path("testdata/")`,
			ctx:    &Context{Content: "a", FilePath: "src/main.go"},
			want:   true,
		},
		{
			name:   "path restriction",
			source: `match("a") and path("\\.env$")`,
			ctx:    &Context{Content: "a", FilePath: "config/.env"},
			want:   true,
		},
		{
			name:   "path matches windows path",
			source: `match("a") and path("testdata/")`,
			ctx:    &Context{Content: "a", FilePath: "x", WindowsFilePath: "testdata/secret.txt"},
			want:   true,
		},
		{
			name:   "complex expression",
			source: `(match("AKIA[0-9A-Z]{16}") and entropy >= 3.0) and not (path("testdata/") or path("docs/"))`,
			ctx:    &Context{Content: "AKIAIOSFODNN7EXAMPLE", Entropy: 3.2, FilePath: "docs/example.md"},
			want:   false,
		},
		{
			name:   "complex expression passing",
			source: `(match("AKIA[0-9A-Z]{16}") and entropy >= 3.0) and not (path("testdata/") or path("docs/"))`,
			ctx:    &Context{Content: "AKIAIOSFODNN7EXAMPLE", Entropy: 3.2, FilePath: "src/config.go"},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.source)
			require.NoError(t, err)
			assert.Equal(t, tt.want, expr.Eval(tt.ctx))
		})
	}
}

func TestMatchTerms(t *testing.T) {
	expr, err := Parse(`match("a") and (match("(b)", 1) or match("a")) and not match("c")`)
	require.NoError(t, err)

	terms := expr.MatchTerms()
	require.Len(t, terms, 3)
	assert.Equal(t, "a", terms[0].Regex.String())
	assert.Equal(t, 0, terms[0].Group)
	assert.Equal(t, "(b)", terms[1].Regex.String())
	assert.Equal(t, 1, terms[1].Group)
	assert.Equal(t, "c", terms[2].Regex.String())
}

func TestPrimary(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantPattern string
	}{
		{name: "single match", source: `match("a")`, wantPattern: "a"},
		{name: "first positive wins", source: `match("a") and match("b")`, wantPattern: "a"},
		{name: "negated terms are skipped", source: `not match("a") and match("b")`, wantPattern: "b"},
		{name: "double negation is positive", source: `not not match("a") and match("b")`, wantPattern: "a"},
		{name: "negated group", source: `not (match("a") or match("b")) and match("c")`, wantPattern: "c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := Parse(tt.source)
			require.NoError(t, err)
			require.NotNil(t, expr.Primary())
			assert.Equal(t, tt.wantPattern, expr.Primary().Regex.String())
		})
	}
}

func TestString(t *testing.T) {
	expr, err := Parse(`match("a") and not path("b")`)
	require.NoError(t, err)
	assert.Equal(t, `(match("a") and not path("b"))`, expr.String())
}
