// yaml.go — 受限 YAML 子集解析器与类型化取值辅助。
//
// 支持语法（覆盖 configs/sentinel.yaml 全部所需）：
//   - "# 注释"（整行或行尾，引号内的 # 不视为注释）
//   - 嵌套映射（缩进表示层级，只允许空格缩进）
//   - 标量：裸字符串 / 双引号 / 单引号字符串
//   - 列表："- 标量" 与 "- key: value"（对象列表，续行与首个 key 对齐）
//   - 流式列表：[a, b, "c d"]（用于 scope: [...] 等短列表）
//   - 空值键（key: 后为空，值取嵌套块或空字符串）
//
// 不支持：锚点/引用、多文档、多行字符串。
package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ---- 解析树结构：map[string]any / []any / string ----

type yamlLine struct {
	indent int
	text   string // 已去缩进、去注释
	num    int    // 原始行号（错误信息用）
}

func parseYAML(data []byte) (map[string]any, error) {
	lines, err := scanLines(data)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	v, next, err := parseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next != len(lines) {
		return nil, fmt.Errorf("第 %d 行: 缩进与上下文不匹配", lines[next].num)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("顶层必须是映射（key: value）")
	}
	return m, nil
}

func scanLines(data []byte) ([]yamlLine, error) {
	var out []yamlLine
	for i, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimRight(raw, "\r")
		stripped := stripComment(raw)
		trimmed := strings.TrimRight(stripped, " \t")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		indent := 0
		for indent < len(trimmed) && trimmed[indent] == ' ' {
			indent++
		}
		if indent < len(trimmed) && trimmed[indent] == '\t' {
			return nil, fmt.Errorf("第 %d 行: 不允许使用 Tab 缩进", i+1)
		}
		text := strings.TrimLeft(trimmed, " ")
		out = append(out, yamlLine{indent: indent, text: text, num: i + 1})
	}
	return out, nil
}

// stripComment 移除引号外第一个 # 之后的注释。
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func isListItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// parseBlock 根据首行内容分派到映射或列表。
func parseBlock(lines []yamlLine, i, indent int) (any, int, error) {
	if isListItem(lines[i].text) {
		return parseList(lines, i, indent)
	}
	return parseMap(lines, i, indent)
}

func parseMap(lines []yamlLine, i, indent int) (any, int, error) {
	m := map[string]any{}
	for i < len(lines) && lines[i].indent == indent && !isListItem(lines[i].text) {
		key, val, ok := splitKV(lines[i].text)
		if !ok {
			return nil, i, fmt.Errorf("第 %d 行: 期望 \"key: value\"，得到 %q", lines[i].num, lines[i].text)
		}
		if val != "" {
			m[key] = parseValue(val)
			i++
			continue
		}
		// 值为空：取嵌套块（更深缩进），或同缩进的列表，或空字符串
		i++
		switch {
		case i < len(lines) && lines[i].indent > indent:
			v, next, err := parseBlock(lines, i, lines[i].indent)
			if err != nil {
				return nil, next, err
			}
			m[key] = v
			i = next
		case i < len(lines) && lines[i].indent == indent && isListItem(lines[i].text):
			v, next, err := parseList(lines, i, indent)
			if err != nil {
				return nil, next, err
			}
			m[key] = v
			i = next
		default:
			m[key] = ""
		}
	}
	return m, i, nil
}

func parseList(lines []yamlLine, i, indent int) (any, int, error) {
	items := []any{}
	for i < len(lines) && lines[i].indent == indent && isListItem(lines[i].text) {
		text := lines[i].text
		if text == "-" {
			// "- " 后内容在更深的缩进
			i++
			if i < len(lines) && lines[i].indent > indent {
				v, next, err := parseBlock(lines, i, lines[i].indent)
				if err != nil {
					return nil, next, err
				}
				items = append(items, v)
				i = next
			} else {
				items = append(items, "")
			}
			continue
		}
		rest := text[2:]
		if _, _, ok := splitKV(rest); ok {
			// 对象列表项：把 "- key: v" 视作缩进 +2 的映射首行，
			// 后续同缩进行会被 parseMap 一并归入该项。
			restIndent := indent + 2
			lines[i] = yamlLine{indent: restIndent, text: rest, num: lines[i].num}
			v, next, err := parseMap(lines, i, restIndent)
			if err != nil {
				return nil, next, err
			}
			items = append(items, v)
			i = next
			continue
		}
		items = append(items, parseValue(rest))
		i++
	}
	return items, i, nil
}

// parseValue 解析标量或流式列表（[a, b, "c d"]）。
func parseValue(s string) any {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}
		}
		parts := splitFlowList(inner)
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			out = append(out, parseScalar(strings.TrimSpace(p)))
		}
		return out
	}
	return parseScalar(s)
}

// splitFlowList 按逗号分割流式列表内容（引号内逗号不分割）。
func splitFlowList(s string) []string {
	var out []string
	var quote byte
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			buf.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
			buf.WriteByte(c)
		case c == ',':
			out = append(out, buf.String())
			buf.Reset()
		default:
			buf.WriteByte(c)
		}
	}
	if buf.Len() > 0 || len(out) > 0 {
		out = append(out, buf.String())
	}
	return out
}

// splitKV 在 "key: value" 中分割（冒号后须跟空格或行尾）。
func splitKV(text string) (key, val string, ok bool) {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ':':
			if i+1 == len(text) || text[i+1] == ' ' {
				return unquote(strings.TrimSpace(text[:i])), strings.TrimSpace(text[i+1:]), true
			}
		}
	}
	return "", "", false
}

func parseScalar(s string) string {
	return unquote(s)
}

func unquote(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return strings.ReplaceAll(strings.Trim(s, `"`), `\"`, `"`)
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return strings.Trim(s, "'")
		}
	}
	return s
}

// ---- 类型化取值辅助（缺省值兜底）----

func getMap(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	sub, ok := v.(map[string]any)
	return sub
}

func getString(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

func getBool(m map[string]any, key string, def bool) bool {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			if b, err := strconv.ParseBool(s); err == nil {
				return b
			}
		}
	}
	return def
}

func getDuration(m map[string]any, key string, def time.Duration) time.Duration {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			// 解析成功即返回（含 <= 0 的值，交给 Validate 拒绝，
			// 避免非法时长被静默替换为默认值）
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
			// 纯数字按秒处理
			if n, err := strconv.Atoi(s); err == nil {
				return time.Duration(n) * time.Second
			}
		}
	}
	return def
}

func getStringList(m map[string]any, key string, def []string) []string {
	v, ok := m[key]
	if !ok {
		return def
	}
	items, ok := v.([]any)
	if !ok {
		return def
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func getAnyList(m map[string]any, key string) []any {
	if v, ok := m[key]; ok {
		if items, ok := v.([]any); ok {
			return items
		}
	}
	return nil
}

// parseIPPort 解析 "1.2.3.4:443" 形式的条目。
func parseIPPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("缺少 :port: %q", s)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return "", 0, fmt.Errorf("不是有效 IPv4: %q", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("端口无效（1-65535）: %q", portStr)
	}
	return host, uint16(port), nil
}
