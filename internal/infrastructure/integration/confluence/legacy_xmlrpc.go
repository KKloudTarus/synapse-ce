package confluence

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxXMLRPCDepth       = 16
	maxXMLRPCScalarBytes = 4096
	maxXMLRPCArrayValues = 100
	maxXMLRPCMembers     = 32
)

type xmlRPCValueKind uint8

const (
	xmlRPCStringKind xmlRPCValueKind = iota
	xmlRPCIntegerKind
	xmlRPCBooleanKind
	xmlRPCStructKind
	xmlRPCArrayKind
)

type xmlRPCValue struct {
	kind    xmlRPCValueKind
	text    string
	members map[string]xmlRPCValue
	array   []xmlRPCValue
}

func xmlRPCString(value string) xmlRPCValue { return xmlRPCValue{kind: xmlRPCStringKind, text: value} }

func xmlRPCInteger(value int64) xmlRPCValue {
	return xmlRPCValue{kind: xmlRPCIntegerKind, text: strconv.FormatInt(value, 10)}
}

func (a *Adapter) legacyXMLRPCPreflight(ctx context.Context, username string) error {
	if username == "" {
		var current struct {
			Username string `json:"username"`
		}
		if err := a.request(ctx, a.client, http.MethodGet, a.apiPath("/user/current"), nil, nil, &current, false, http.StatusOK); err != nil {
			return err
		}
		username = current.Username
	}
	if !safeIdentifier(username, 255) || a.containsCredential(username) {
		return providerError(http.StatusOK, "invalid_identity", false)
	}
	server, err := a.legacyXMLRPCRequest(ctx, "confluence2.getServerInfo", []xmlRPCValue{xmlRPCString("")}, false)
	if err != nil {
		return err
	}
	if server.kind != xmlRPCStructKind || server.members["majorVersion"].text != "10" || server.members["minorVersion"].text != "2" {
		return providerError(http.StatusOK, "legacy_xmlrpc_unsupported", false)
	}
	groups, err := a.legacyXMLRPCRequest(ctx, "confluence2.getUserGroups", []xmlRPCValue{xmlRPCString(""), xmlRPCString(username)}, false)
	if err != nil {
		return err
	}
	if groups.kind != xmlRPCArrayKind {
		return providerError(http.StatusOK, "legacy_xmlrpc_unverified", false)
	}
	for _, group := range groups.array {
		if group.kind != xmlRPCStringKind || !safeIdentifier(group.text, 255) || a.containsCredential(group.text) {
			return providerError(http.StatusOK, "legacy_xmlrpc_unverified", false)
		}
		if group.text == a.readGroup {
			return nil
		}
	}
	return providerError(http.StatusOK, "legacy_xmlrpc_unverified", false)
}

func (a *Adapter) setLegacyXMLRPCPermissions(ctx context.Context, page, group string) error {
	pageID, err := strconv.ParseInt(page, 10, 64)
	if err != nil || pageID <= 0 {
		return providerError(0, "invalid_restriction", false)
	}
	for _, operation := range []string{"View", "Edit"} {
		if err := a.legacyXMLRPCPreflight(ctx, ""); err != nil {
			return err
		}
		permissions := xmlRPCValue{kind: xmlRPCArrayKind, array: []xmlRPCValue{{kind: xmlRPCStructKind, members: map[string]xmlRPCValue{
			"type":      xmlRPCString(operation),
			"groupName": xmlRPCString(group),
		}}}}
		response, err := a.legacyXMLRPCRequest(ctx, "confluence2.setContentPermissions", []xmlRPCValue{xmlRPCString(""), xmlRPCInteger(pageID), xmlRPCString(operation), permissions}, true)
		if err != nil {
			return err
		}
		if response.kind != xmlRPCBooleanKind || response.text != "1" {
			return providerError(http.StatusOK, "legacy_xmlrpc_invalid_response", true)
		}
	}
	return nil
}

func (a *Adapter) legacyXMLRPCRequest(ctx context.Context, method string, values []xmlRPCValue, write bool) (xmlRPCValue, error) {
	if !a.legacyXMLRPCMethod(method, len(values)) {
		return xmlRPCValue{}, providerError(0, "invalid_request", false)
	}
	body, err := marshalXMLRPCRequest(method, values)
	if err != nil {
		return xmlRPCValue{}, providerError(0, "invalid_request", false)
	}
	var raw responseBytes
	headers := http.Header{"Accept": {"text/xml"}, "Content-Type": {"text/xml; charset=utf-8"}}
	if err := a.requestWithHeaders(ctx, a.client, http.MethodPost, a.legacyXMLRPCPath(), nil, body, &raw, headers, write, http.StatusOK); err != nil {
		return xmlRPCValue{}, err
	}
	value, err := parseXMLRPCResponse(raw)
	if err != nil {
		return xmlRPCValue{}, providerError(http.StatusOK, "legacy_xmlrpc_invalid_response", write)
	}
	return value, nil
}

func (a *Adapter) legacyXMLRPCMethod(method string, valueCount int) bool {
	switch method {
	case "confluence2.getServerInfo":
		return valueCount == 1
	case "confluence2.getUserGroups":
		return valueCount == 2
	case "confluence2.setContentPermissions":
		return valueCount == 4
	default:
		return false
	}
}

func (a *Adapter) legacyXMLRPCPath() string {
	return strings.TrimSuffix(a.base.Path, "/") + "/rpc/xmlrpc"
}

func marshalXMLRPCRequest(method string, values []xmlRPCValue) ([]byte, error) {
	var out strings.Builder
	out.Grow(256)
	out.WriteString(`<?xml version="1.0"?><methodCall><methodName>`)
	writeXMLRPCText(&out, method)
	out.WriteString(`</methodName><params>`)
	for _, value := range values {
		encoded, err := marshalXMLRPCValue(value, 0)
		if err != nil {
			return nil, err
		}
		out.WriteString("<param>")
		out.WriteString(encoded)
		out.WriteString("</param>")
	}
	out.WriteString(`</params></methodCall>`)
	return []byte(out.String()), nil
}

func marshalXMLRPCValue(value xmlRPCValue, depth int) (string, error) {
	if depth >= maxXMLRPCDepth {
		return "", fmt.Errorf("XML-RPC value is too deep")
	}
	var out strings.Builder
	out.WriteString("<value>")
	switch value.kind {
	case xmlRPCStringKind:
		if !validXMLRPCScalar(value.text) {
			return "", fmt.Errorf("invalid XML-RPC string")
		}
		out.WriteString("<string>")
		writeXMLRPCText(&out, value.text)
		out.WriteString("</string>")
	case xmlRPCIntegerKind:
		if _, err := strconv.ParseInt(value.text, 10, 64); err != nil {
			return "", fmt.Errorf("invalid XML-RPC integer")
		}
		out.WriteString("<i8>")
		out.WriteString(value.text)
		out.WriteString("</i8>")
	case xmlRPCBooleanKind:
		if value.text != "0" && value.text != "1" {
			return "", fmt.Errorf("invalid XML-RPC boolean")
		}
		out.WriteString("<boolean>")
		out.WriteString(value.text)
		out.WriteString("</boolean>")
	case xmlRPCStructKind:
		if len(value.members) == 0 || len(value.members) > maxXMLRPCMembers {
			return "", fmt.Errorf("invalid XML-RPC struct")
		}
		out.WriteString("<struct>")
		for _, name := range []string{"type", "groupName"} {
			member, ok := value.members[name]
			if !ok {
				continue
			}
			if member.kind != xmlRPCStringKind || !validXMLRPCScalar(member.text) {
				return "", fmt.Errorf("invalid XML-RPC struct member")
			}
			out.WriteString("<member><name>")
			writeXMLRPCText(&out, name)
			out.WriteString("</name>")
			encoded, err := marshalXMLRPCValue(member, depth+1)
			if err != nil {
				return "", err
			}
			out.WriteString(encoded)
			out.WriteString("</member>")
		}
		if len(value.members) != 2 {
			return "", fmt.Errorf("unsupported XML-RPC struct member")
		}
		out.WriteString("</struct>")
	case xmlRPCArrayKind:
		if len(value.array) > maxXMLRPCArrayValues {
			return "", fmt.Errorf("XML-RPC array too large")
		}
		out.WriteString("<array><data>")
		for _, item := range value.array {
			encoded, err := marshalXMLRPCValue(item, depth+1)
			if err != nil {
				return "", err
			}
			out.WriteString(encoded)
		}
		out.WriteString("</data></array>")
	default:
		return "", fmt.Errorf("unsupported XML-RPC value")
	}
	out.WriteString("</value>")
	return out.String(), nil
}

func writeXMLRPCText(out *strings.Builder, value string) {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(value))
	out.Write(escaped.Bytes())
}

func validXMLRPCScalar(value string) bool {
	return len(value) <= maxXMLRPCScalarBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func parseXMLRPCResponse(raw []byte) (xmlRPCValue, error) {
	if len(raw) == 0 || len(raw) > maxResponseBytes || bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE")) || bytes.Contains(bytes.ToUpper(raw), []byte("<!ENTITY")) {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC response")
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	start, err := nextXMLRPCStart(decoder)
	if err != nil || start.Name.Local != "methodResponse" {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC response")
	}
	next, err := nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	section, ok := next.(xml.StartElement)
	if !ok {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC response")
	}
	if section.Name.Local == "fault" {
		return xmlRPCValue{}, fmt.Errorf("XML-RPC fault")
	}
	if section.Name.Local != "params" {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC response")
	}
	value, err := parseXMLRPCParams(decoder, 1)
	if err != nil {
		return xmlRPCValue{}, err
	}
	end, err := nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	if close, ok := end.(xml.EndElement); !ok || close.Name.Local != "methodResponse" {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC response")
	}
	if _, err := nextXMLRPCToken(decoder); err != io.EOF {
		return xmlRPCValue{}, fmt.Errorf("trailing XML-RPC response")
	}
	return value, nil
}

func nextXMLRPCStart(decoder *xml.Decoder) (xml.StartElement, error) {
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return xml.StartElement{}, err
	}
	start, ok := token.(xml.StartElement)
	if !ok || len(start.Attr) != 0 {
		return xml.StartElement{}, fmt.Errorf("invalid XML-RPC root")
	}
	return start, nil
}

func nextXMLRPCToken(decoder *xml.Decoder) (xml.Token, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) == "" {
				continue
			}
			return token, nil
		case xml.ProcInst:
			if strings.EqualFold(value.Target, "xml") {
				continue
			}
			return nil, fmt.Errorf("processing instruction is not allowed")
		case xml.Directive, xml.Comment:
			return nil, fmt.Errorf("XML directive is not allowed")
		default:
			return token, nil
		}
	}
}

func parseXMLRPCParams(decoder *xml.Decoder, depth int) (xmlRPCValue, error) {
	if depth >= maxXMLRPCDepth {
		return xmlRPCValue{}, fmt.Errorf("XML-RPC response too deep")
	}
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	param, ok := token.(xml.StartElement)
	if !ok || param.Name.Local != "param" || len(param.Attr) != 0 {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC params")
	}
	token, err = nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	start, ok := token.(xml.StartElement)
	if !ok || start.Name.Local != "value" || len(start.Attr) != 0 {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC param")
	}
	value, err := parseXMLRPCValue(decoder, depth+1)
	if err != nil {
		return xmlRPCValue{}, err
	}
	token, err = nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	if close, ok := token.(xml.EndElement); !ok || close.Name.Local != "param" {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC param")
	}
	token, err = nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	if close, ok := token.(xml.EndElement); !ok || close.Name.Local != "params" {
		return xmlRPCValue{}, fmt.Errorf("XML-RPC response requires one param")
	}
	return value, nil
}

func parseXMLRPCValue(decoder *xml.Decoder, depth int) (xmlRPCValue, error) {
	if depth >= maxXMLRPCDepth {
		return xmlRPCValue{}, fmt.Errorf("XML-RPC response too deep")
	}
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return xmlRPCValue{}, err
	}
	if close, ok := token.(xml.EndElement); ok && close.Name.Local == "value" {
		return xmlRPCString(""), nil
	}
	if text, ok := token.(xml.CharData); ok {
		valueText := string(append([]byte(nil), text...))
		if !validXMLRPCScalar(valueText) {
			return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC scalar")
		}
		if err := expectXMLRPCEnd(decoder, "value"); err != nil {
			return xmlRPCValue{}, err
		}
		return xmlRPCString(valueText), nil
	}
	start, ok := token.(xml.StartElement)
	if !ok || len(start.Attr) != 0 {
		return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC value")
	}
	var value xmlRPCValue
	switch start.Name.Local {
	case "string":
		text, err := parseXMLRPCText(decoder, "string")
		if err != nil {
			return xmlRPCValue{}, err
		}
		value = xmlRPCString(text)
	case "int", "i4", "i8":
		text, err := parseXMLRPCText(decoder, start.Name.Local)
		if err != nil || !validXMLRPCInteger(text) {
			return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC integer")
		}
		value = xmlRPCValue{kind: xmlRPCIntegerKind, text: text}
	case "boolean":
		text, err := parseXMLRPCText(decoder, "boolean")
		if err != nil || (text != "0" && text != "1") {
			return xmlRPCValue{}, fmt.Errorf("invalid XML-RPC boolean")
		}
		value = xmlRPCValue{kind: xmlRPCBooleanKind, text: text}
	case "struct":
		members, err := parseXMLRPCStruct(decoder, depth+1)
		if err != nil {
			return xmlRPCValue{}, err
		}
		value = xmlRPCValue{kind: xmlRPCStructKind, members: members}
	case "array":
		array, err := parseXMLRPCArray(decoder, depth+1)
		if err != nil {
			return xmlRPCValue{}, err
		}
		value = xmlRPCValue{kind: xmlRPCArrayKind, array: array}
	default:
		return xmlRPCValue{}, fmt.Errorf("unsupported XML-RPC value")
	}
	if err := expectXMLRPCEnd(decoder, "value"); err != nil {
		return xmlRPCValue{}, err
	}
	return value, nil
}

func parseXMLRPCText(decoder *xml.Decoder, name string) (string, error) {
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return "", err
	}
	text := ""
	if char, ok := token.(xml.CharData); ok {
		text = string(append([]byte(nil), char...))
		if !validXMLRPCScalar(text) {
			return "", fmt.Errorf("invalid XML-RPC scalar")
		}
		if err := expectXMLRPCEnd(decoder, name); err != nil {
			return "", err
		}
		return text, nil
	}
	if close, ok := token.(xml.EndElement); ok && close.Name.Local == name {
		return text, nil
	}
	return "", fmt.Errorf("invalid XML-RPC text")
}

func parseXMLRPCStruct(decoder *xml.Decoder, depth int) (map[string]xmlRPCValue, error) {
	members := make(map[string]xmlRPCValue)
	for {
		token, err := nextXMLRPCToken(decoder)
		if err != nil {
			return nil, err
		}
		if close, ok := token.(xml.EndElement); ok && close.Name.Local == "struct" {
			if len(members) == 0 {
				return nil, fmt.Errorf("empty XML-RPC struct")
			}
			return members, nil
		}
		member, ok := token.(xml.StartElement)
		if !ok || member.Name.Local != "member" || len(member.Attr) != 0 || len(members) >= maxXMLRPCMembers {
			return nil, fmt.Errorf("invalid XML-RPC struct")
		}
		name, value, err := parseXMLRPCMember(decoder, depth+1)
		if err != nil || name == "" || !safeIdentifier(name, 255) {
			return nil, fmt.Errorf("invalid XML-RPC member")
		}
		if _, duplicate := members[name]; duplicate {
			return nil, fmt.Errorf("duplicate XML-RPC member")
		}
		members[name] = value
	}
}

func parseXMLRPCMember(decoder *xml.Decoder, depth int) (string, xmlRPCValue, error) {
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return "", xmlRPCValue{}, err
	}
	start, ok := token.(xml.StartElement)
	if !ok || start.Name.Local != "name" || len(start.Attr) != 0 {
		return "", xmlRPCValue{}, fmt.Errorf("invalid XML-RPC member")
	}
	name, err := parseXMLRPCText(decoder, "name")
	if err != nil {
		return "", xmlRPCValue{}, err
	}
	token, err = nextXMLRPCToken(decoder)
	if err != nil {
		return "", xmlRPCValue{}, err
	}
	start, ok = token.(xml.StartElement)
	if !ok || start.Name.Local != "value" || len(start.Attr) != 0 {
		return "", xmlRPCValue{}, fmt.Errorf("invalid XML-RPC member")
	}
	value, err := parseXMLRPCValue(decoder, depth+1)
	if err != nil {
		return "", xmlRPCValue{}, err
	}
	if err := expectXMLRPCEnd(decoder, "member"); err != nil {
		return "", xmlRPCValue{}, err
	}
	return name, value, nil
}

func parseXMLRPCArray(decoder *xml.Decoder, depth int) ([]xmlRPCValue, error) {
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return nil, err
	}
	data, ok := token.(xml.StartElement)
	if !ok || data.Name.Local != "data" || len(data.Attr) != 0 {
		return nil, fmt.Errorf("invalid XML-RPC array")
	}
	values := make([]xmlRPCValue, 0)
	for {
		token, err := nextXMLRPCToken(decoder)
		if err != nil {
			return nil, err
		}
		if close, ok := token.(xml.EndElement); ok && close.Name.Local == "data" {
			if err := expectXMLRPCEnd(decoder, "array"); err != nil {
				return nil, err
			}
			return values, nil
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "value" || len(start.Attr) != 0 || len(values) >= maxXMLRPCArrayValues {
			return nil, fmt.Errorf("invalid XML-RPC array")
		}
		value, err := parseXMLRPCValue(decoder, depth+1)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
}

func expectXMLRPCEnd(decoder *xml.Decoder, name string) error {
	token, err := nextXMLRPCToken(decoder)
	if err != nil {
		return err
	}
	if close, ok := token.(xml.EndElement); !ok || close.Name.Local != name {
		return fmt.Errorf("invalid XML-RPC close")
	}
	return nil
}

func validXMLRPCInteger(value string) bool {
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}
