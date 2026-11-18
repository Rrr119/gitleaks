package dsl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.tokens[p.pos]
	if t.kind != tokenEOF {
		p.pos++
	}
	return t
}

func (p *parser) expect(kind tokenKind, what string) (token, error) {
	t := p.peek()
	if t.kind != kind {
		return t, fmt.Errorf("expected %s, got %s at position %d", what, t, t.pos)
	}
	return p.next(), nil
}

func (p *parser) parseExpr() (Node, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokenOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Or{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokenAnd {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &And{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (Node, error) {
	if p.peek().kind == tokenNot {
		p.next()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Not{Operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	t := p.peek()
	switch t.kind {
	case tokenLParen:
		p.next()
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokenRParen, "')'"); err != nil {
			return nil, err
		}
		return expr, nil
	case tokenIdent:
		switch strings.ToLower(t.text) {
		case "match":
			return p.parseMatch()
		case "path":
			return p.parsePath()
		case "entropy":
			return p.parseEntropy()
		default:
			return nil, fmt.Errorf("unknown function '%s' at position %d (expected 'match', 'path', or 'entropy')", t.text, t.pos)
		}
	default:
		return nil, fmt.Errorf("unexpected %s at position %d", t, t.pos)
	}
}

func (p *parser) parseMatch() (Node, error) {
	p.next() // consume 'match'
	if _, err := p.expect(tokenLParen, "'(' after 'match'"); err != nil {
		return nil, err
	}
	patternTok, err := p.expect(tokenString, "regex string")
	if err != nil {
		return nil, err
	}

	group := 0
	if p.peek().kind == tokenComma {
		p.next()
		groupTok, err := p.expect(tokenNumber, "secret group number")
		if err != nil {
			return nil, err
		}
		g, err := strconv.Atoi(groupTok.text)
		if err != nil || g < 0 {
			return nil, fmt.Errorf("invalid secret group '%s' at position %d (expected a non-negative integer)", groupTok.text, groupTok.pos)
		}
		group = g
	}
	if _, err := p.expect(tokenRParen, "')'"); err != nil {
		return nil, err
	}

	re, err := compileRegex(patternTok.text)
	if err != nil {
		return nil, fmt.Errorf("invalid match() regex at position %d: %w", patternTok.pos, err)
	}
	if group > re.NumSubexp() {
		return nil, fmt.Errorf("invalid match() secret group %d at position %d, regex only has %d capture group(s)", group, patternTok.pos, re.NumSubexp())
	}
	return &Match{Regex: re, Group: group, raw: patternTok.text}, nil
}

func (p *parser) parsePath() (Node, error) {
	p.next() // consume 'path'
	if _, err := p.expect(tokenLParen, "'(' after 'path'"); err != nil {
		return nil, err
	}
	patternTok, err := p.expect(tokenString, "regex string")
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tokenRParen, "')'"); err != nil {
		return nil, err
	}

	re, err := compileRegex(patternTok.text)
	if err != nil {
		return nil, fmt.Errorf("invalid path() regex at position %d: %w", patternTok.pos, err)
	}
	return &Path{Regex: re, raw: patternTok.text}, nil
}

func (p *parser) parseEntropy() (Node, error) {
	p.next() // consume 'entropy'
	opTok, err := p.expect(tokenCmpOp, "comparison operator after 'entropy' (>, >=, <, <=, ==, !=)")
	if err != nil {
		return nil, err
	}
	valueTok, err := p.expect(tokenNumber, "entropy threshold number")
	if err != nil {
		return nil, err
	}
	value, _ := strconv.ParseFloat(valueTok.text, 64)
	if value < 0 {
		return nil, fmt.Errorf("invalid entropy threshold %g at position %d (must be non-negative)", value, valueTok.pos)
	}
	return &Entropy{Op: opTok.text, Value: value}, nil
}

func compileRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}
