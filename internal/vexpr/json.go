package vexpr

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// layout is the whitespace of a JSON file this package rewrites: enough to put
// back what was there rather than what encoding/json would have chosen.
//
// It exists because the diff is the product. A one-statement change to
// rancher/vexhub's 4381-line index should be four added lines; re-indenting to
// this package's taste would make it 4381 changed lines and bury the thing a
// maintainer is being asked to review. Two spaces and a trailing newline are
// the defaults, matching every published hub seen so far, and a file that
// disagrees keeps its own.
type layout struct {
	indent  string
	lastNL  bool
	learned bool
}

// defaultLayout is what a file created here looks like.
func defaultLayout() layout { return layout{indent: "  ", lastNL: true, learned: true} }

// detectLayout reads a JSON file's formatting off the file.
//
// The indent is the leading whitespace of the first indented line, which is how
// an indent unit is expressed in a pretty-printed object; a file that is not
// pretty-printed leaves it empty and is re-emitted the same way.
func detectLayout(b []byte) layout {
	l := layout{lastNL: bytes.HasSuffix(b, []byte("\n")), learned: true}
	for _, line := range bytes.Split(b, []byte("\n"))[1:] {
		trimmed := bytes.TrimLeft(line, " \t")
		if len(trimmed) == 0 {
			continue
		}
		l.indent = string(line[:len(line)-len(trimmed)])
		break
	}
	return l
}

// render pretty-prints compact JSON in this layout.
func (l layout) render(compact []byte) ([]byte, error) {
	if !l.learned {
		l = defaultLayout()
	}
	out := compact
	if l.indent != "" {
		var buf bytes.Buffer
		if err := json.Indent(&buf, compact, "", l.indent); err != nil {
			return nil, err
		}
		out = buf.Bytes()
	}
	if l.lastNL {
		out = append(out, '\n')
	}
	return out, nil
}

// marshalNoEscape renders v as compact JSON without HTML-escaping &, < and >, so
// preserved bytes and URLs round-trip unchanged instead of turning into \u00xx
// escapes that would show up as spurious diff noise on untouched vendor lines.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// setRawField sets a field's value, appending its key to order only if it was
// not already present so existing keys keep their position.
func setRawField(order []string, fields map[string]json.RawMessage, key string, val json.RawMessage) []string {
	if _, ok := fields[key]; !ok {
		order = append(order, key)
	}
	fields[key] = val
	return order
}

// marshalOrderedObject renders a JSON object with its keys in the given order,
// writing each field's raw value verbatim.
func marshalOrderedObject(order []string, fields map[string]json.RawMessage) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	seen := make(map[string]bool, len(order))
	first := true
	for _, k := range order {
		v, ok := fields[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// objectKeyOrder returns the top-level keys of a JSON object in the order they
// appear, so a re-marshaled document keeps the original field order.
func objectKeyOrder(b []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, nil
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("vexpr: unexpected object key %v", keyTok)
		}
		keys = append(keys, key)
		if err := skipJSONValue(dec); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// skipJSONValue consumes the next value from dec, descending through nested
// objects and arrays so the decoder is left positioned after it.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}
