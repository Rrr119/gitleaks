package dsl

import (
	"fmt"
	"strconv"
	"strings"
)

type tokenKind int

const (
	tokenEOF tokenKind = iota
	tokenIdent
	tokenString
	tokenNumber
	tokenLParen
	tokenRParen
	tokenComma
	tokenAnd   // and, &&
	tokenOr    // or, ||
	tokenNot   // not, !
	tokenCmpOp // >, >=, <, <=, ==, !=
)

type token struct {
	kind tokenKind
	// text is the raw text of the token. For strings it is the unquoted,
	// unescaped value.
	text string
	pos  int
}

func (t token) String() string {
	switch t.kind {
	case tokenEOF:
		return "end of expression"
	case tokenString:
		return fmt.Sprintf("string %q", t.text)
	default:
		return fmt.Sprintf("'%s'", t.text)
	}
}

func lex(source string) ([]token, error) {
	var tokens []token
	i := 0
	for i < len(source) {
		c := source[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			tokens = append(tokens, token{kind: tokenLParen, text: "(", pos: i})
			i++
		case c == ')':
			tokens = append(tokens, token{kind: tokenRParen, text: ")", pos: i})
			i++
		case c == ',':
			tokens = append(tokens, token{kind: tokenComma, text: ",", pos: i})
			i++
		case c == '&':
			if i+1 >= len(source) || source[i+1] != '&' {
				return nil, lexError(source, i, "expected '&&'")
			}
			tokens = append(tokens, token{kind: tokenAnd, text: "&&", pos: i})
			i += 2
		case c == '|':
			if i+1 >= len(source) || source[i+1] != '|' {
				return nil, lexError(source, i, "expected '||'")
			}
			tokens = append(tokens, token{kind: tokenOr, text: "||", pos: i})
			i += 2
		case c == '!':
			if i+1 < len(source) && source[i+1] == '=' {
				tokens = append(tokens, token{kind: tokenCmpOp, text: "!=", pos: i})
				i += 2
			} else {
				tokens = append(tokens, token{kind: tokenNot, text: "!", pos: i})
				i++
			}
		case c == '=':
			if i+1 >= len(source) || source[i+1] != '=' {
				return nil, lexError(source, i, "expected '=='")
			}
			tokens = append(tokens, token{kind: tokenCmpOp, text: "==", pos: i})
			i += 2
		case c == '>' || c == '<':
			if i+1 < len(source) && source[i+1] == '=' {
				tokens = append(tokens, token{kind: tokenCmpOp, text: string([]byte{c, '='}), pos: i})
				i += 2
			} else {
				tokens = append(tokens, token{kind: tokenCmpOp, text: string(c), pos: i})
				i++
			}
		case c == '"':
			str, n, err := lexString(source[i:])
			if err != nil {
				return nil, lexError(source, i, err.Error())
			}
			tokens = append(tokens, token{kind: tokenString, text: str, pos: i})
			i += n
		case isDigit(c) || (c == '.' && i+1 < len(source) && isDigit(source[i+1])):
			j := i
			for j < len(source) && (isDigit(source[j]) || source[j] == '.') {
				j++
			}
			text := source[i:j]
			if _, err := strconv.ParseFloat(text, 64); err != nil {
				return nil, lexError(source, i, fmt.Sprintf("invalid number '%s'", text))
			}
			tokens = append(tokens, token{kind: tokenNumber, text: text, pos: i})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(source) && isIdentPart(source[j]) {
				j++
			}
			word := source[i:j]
			switch strings.ToLower(word) {
			case "and":
				tokens = append(tokens, token{kind: tokenAnd, text: word, pos: i})
			case "or":
				tokens = append(tokens, token{kind: tokenOr, text: word, pos: i})
			case "not":
				tokens = append(tokens, token{kind: tokenNot, text: word, pos: i})
			default:
				tokens = append(tokens, token{kind: tokenIdent, text: word, pos: i})
			}
			i = j
		default:
			return nil, lexError(source, i, fmt.Sprintf("unexpected character %q", c))
		}
	}
	tokens = append(tokens, token{kind: tokenEOF, pos: len(source)})
	return tokens, nil
}

// lexString lexes a double-quoted string starting at source[0] == '"'.
// It returns the unescaped value and the number of bytes consumed.
func lexString(source string) (string, int, error) {
	i := 1
	for i < len(source) {
		if source[i] == '\\' {
			i += 2
			continue
		}
		if source[i] == '"' {
			unescaped, err := unescapeString(source[1:i])
			if err != nil {
				return "", 0, err
			}
			return unescaped, i + 1, nil
		}
		i++
	}
	return "", 0, fmt.Errorf("unterminated string literal")
}

// unescapeString processes escape sequences in a string literal. Only \",
// \\, \n, \t, and \r are treated as escapes; any other backslash sequence
// (e.g. regex classes like \d, \s, \w) is preserved as-is.
func unescapeString(s string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("invalid escape sequence at end of string")
		}
		switch s[i] {
		case '"':
			sb.WriteByte('"')
		case '\\':
			sb.WriteByte('\\')
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case 'r':
			sb.WriteByte('\r')
		default:
			sb.WriteByte('\\')
			sb.WriteByte(s[i])
		}
	}
	return sb.String(), nil
}

func lexError(source string, pos int, msg string) error {
	return fmt.Errorf("%s at position %d", msg, pos)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }
