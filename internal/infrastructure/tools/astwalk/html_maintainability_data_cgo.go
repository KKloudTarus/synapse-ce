//go:build cgo

package astwalk

const (
	maxHTMLNameNodes      = 4096
	maxHTMLNameBytes      = 4096
	maxHTMLReferenceDepth = 8
	maxHTMLRelationTokens = 256
)

var htmlConcreteARIARoles = map[string]bool{
	"alert": true, "alertdialog": true, "application": true, "article": true,
	"banner": true, "blockquote": true, "button": true, "caption": true,
	"cell": true, "checkbox": true, "code": true, "columnheader": true,
	"combobox": true, "complementary": true, "contentinfo": true, "definition": true,
	"deletion": true, "dialog": true, "directory": true, "document": true,
	"emphasis": true, "feed": true, "figure": true, "form": true,
	"generic": true, "grid": true, "gridcell": true, "group": true,
	"heading": true, "img": true, "insertion": true, "link": true,
	"list": true, "listbox": true, "listitem": true, "log": true,
	"main": true, "marquee": true, "math": true, "menu": true,
	"menubar": true, "menuitem": true, "menuitemcheckbox": true, "menuitemradio": true,
	"meter": true, "navigation": true, "none": true, "note": true,
	"option": true, "paragraph": true, "presentation": true, "progressbar": true,
	"radio": true, "radiogroup": true, "region": true, "row": true,
	"rowgroup": true, "rowheader": true, "scrollbar": true, "search": true,
	"searchbox": true, "separator": true, "slider": true, "spinbutton": true,
	"status": true, "strong": true, "subscript": true, "superscript": true,
	"switch": true, "tab": true, "table": true, "tablist": true,
	"tabpanel": true, "term": true, "textbox": true, "time": true,
	"timer": true, "toolbar": true, "tooltip": true, "tree": true,
	"treegrid": true, "treeitem": true,
}

var htmlARIAReferenceAttributes = map[string]bool{
	"aria-labelledby":       true,
	"aria-describedby":      true,
	"aria-controls":         true,
	"aria-owns":             true,
	"aria-details":          true,
	"aria-errormessage":     true,
	"aria-activedescendant": true,
	"aria-flowto":           true,
}

var htmlARIARequiredProperties = map[string][]string{
	"checkbox":         {"aria-checked"},
	"combobox":         {"aria-controls", "aria-expanded"},
	"heading":          {"aria-level"},
	"menuitemcheckbox": {"aria-checked"},
	"menuitemradio":    {"aria-checked"},
	"radio":            {"aria-checked"},
	"scrollbar":        {"aria-controls", "aria-valuenow"},
	"separator":        {"aria-valuenow"},
	"slider":           {"aria-valuenow"},
	"switch":           {"aria-checked"},
	"meter":            {"aria-valuenow"},
}

var htmlDeprecatedTags = map[string]bool{
	"applet": true, "acronym": true, "bgsound": true, "dir": true,
	"frame": true, "frameset": true, "noframes": true, "isindex": true,
	"keygen": true, "listing": true, "menuitem": true, "nextid": true,
	"noembed": true, "param": true, "plaintext": true, "rb": true,
	"rtc": true, "strike": true, "xmp": true, "basefont": true,
	"big": true, "blink": true, "center": true, "font": true,
	"marquee": true, "multicol": true, "nobr": true, "spacer": true,
	"tt": true,
}

var htmlAlwaysDeprecatedAttributes = map[string]bool{
	"contextmenu": true,
	"onshow":      true,
	"dropzone":    true,
}

func htmlDeprecatedAttributeSet(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

var htmlDeprecatedAttributes = map[string]map[string]bool{
	"a": htmlDeprecatedAttributeSet(
		"charset", "coords", "shape", "methods", "name", "rev", "urn", "datasrc", "datafld",
	),
	"area": htmlDeprecatedAttributeSet("nohref"),
	"body": htmlDeprecatedAttributeSet(
		"alink", "bgcolor", "bottommargin", "leftmargin", "link", "marginheight", "marginwidth",
		"rightmargin", "text", "topmargin", "vlink", "background",
	),
	"br":       htmlDeprecatedAttributeSet("clear"),
	"button":   htmlDeprecatedAttributeSet("datasrc", "datafld", "dataformatas"),
	"caption":  htmlDeprecatedAttributeSet("align"),
	"col":      htmlDeprecatedAttributeSet("align", "char", "charoff", "valign", "width"),
	"div":      htmlDeprecatedAttributeSet("align", "datasrc", "datafld", "dataformatas"),
	"dl":       htmlDeprecatedAttributeSet("compact"),
	"embed":    htmlDeprecatedAttributeSet("name", "align", "hspace", "vspace"),
	"fieldset": htmlDeprecatedAttributeSet("datafld"),
	"form":     htmlDeprecatedAttributeSet("accept"),
	"h1":       htmlDeprecatedAttributeSet("align"),
	"h2":       htmlDeprecatedAttributeSet("align"),
	"h3":       htmlDeprecatedAttributeSet("align"),
	"h4":       htmlDeprecatedAttributeSet("align"),
	"h5":       htmlDeprecatedAttributeSet("align"),
	"h6":       htmlDeprecatedAttributeSet("align"),
	"head":     htmlDeprecatedAttributeSet("profile"),
	"html":     htmlDeprecatedAttributeSet("manifest", "version"),
	"hr":       htmlDeprecatedAttributeSet("align", "color", "noshade", "size", "width"),
	"iframe": htmlDeprecatedAttributeSet(
		"longdesc", "align", "allowtransparency", "frameborder", "framespacing", "hspace",
		"marginheight", "marginwidth", "scrolling", "vspace", "datasrc", "datafld",
	),
	"img": htmlDeprecatedAttributeSet(
		"name", "longdesc", "lowsrc", "align", "border", "hspace", "vspace", "datasrc", "datafld",
	),
	"input": htmlDeprecatedAttributeSet(
		"ismap", "usemap", "align", "border", "hspace", "vspace", "datasrc", "datafld", "dataformatas",
	),
	"label":  htmlDeprecatedAttributeSet("datasrc", "datafld", "dataformatas"),
	"legend": htmlDeprecatedAttributeSet("align", "datasrc", "datafld", "dataformatas"),
	"li":     htmlDeprecatedAttributeSet("type"),
	"link":   htmlDeprecatedAttributeSet("charset", "methods", "rev", "urn", "target"),
	"menu":   htmlDeprecatedAttributeSet("type", "label", "compact"),
	"meta":   htmlDeprecatedAttributeSet("scheme"),
	"object": htmlDeprecatedAttributeSet(
		"usemap", "archive", "classid", "code", "codebase", "codetype", "declare", "standby",
		"typemustmatch", "align", "border", "hspace", "vspace", "datasrc", "datafld", "dataformatas",
	),
	"ol":     htmlDeprecatedAttributeSet("compact"),
	"option": htmlDeprecatedAttributeSet("name", "datasrc", "dataformatas"),
	"p":      htmlDeprecatedAttributeSet("align"),
	"pre":    htmlDeprecatedAttributeSet("width"),
	"script": htmlDeprecatedAttributeSet("charset", "language", "event", "for"),
	"select": htmlDeprecatedAttributeSet("datasrc", "datafld", "dataformatas"),
	"span":   htmlDeprecatedAttributeSet("datasrc", "datafld", "dataformatas"),
	"style":  htmlDeprecatedAttributeSet("type"),
	"table": htmlDeprecatedAttributeSet(
		"datapagesize", "summary", "datasrc", "dataformatas", "align", "bgcolor", "border",
		"bordercolor", "cellpadding", "cellspacing", "frame", "height", "rules", "width", "background",
	),
	"td": htmlDeprecatedAttributeSet(
		"abbr", "axis", "scope", "align", "bgcolor", "char", "charoff", "height", "nowrap",
		"valign", "width", "background",
	),
	"th": htmlDeprecatedAttributeSet(
		"axis", "align", "bgcolor", "char", "charoff", "height", "nowrap", "valign", "width", "background",
	),
	"thead":    htmlDeprecatedAttributeSet("align", "char", "charoff", "height", "valign", "background"),
	"tbody":    htmlDeprecatedAttributeSet("align", "char", "charoff", "height", "valign", "background"),
	"tfoot":    htmlDeprecatedAttributeSet("align", "char", "charoff", "height", "valign", "background"),
	"tr":       htmlDeprecatedAttributeSet("align", "bgcolor", "char", "charoff", "height", "valign", "background"),
	"textarea": htmlDeprecatedAttributeSet("datasrc", "datafld"),
	"ul":       htmlDeprecatedAttributeSet("compact", "type"),
	"frame":    htmlDeprecatedAttributeSet("datasrc", "datafld"),
	"marquee":  htmlDeprecatedAttributeSet("datasrc", "datafld", "dataformatas"),
}

var htmlJavaScriptMIMEEssences = map[string]bool{
	"application/ecmascript":   true,
	"application/javascript":   true,
	"application/x-ecmascript": true,
	"application/x-javascript": true,
	"text/ecmascript":          true,
	"text/javascript":          true,
	"text/javascript1.0":       true,
	"text/javascript1.1":       true,
	"text/javascript1.2":       true,
	"text/javascript1.3":       true,
	"text/javascript1.4":       true,
	"text/javascript1.5":       true,
	"text/jscript":             true,
	"text/livescript":          true,
	"text/x-ecmascript":        true,
	"text/x-javascript":        true,
}
