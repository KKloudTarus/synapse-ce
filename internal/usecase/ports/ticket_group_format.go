package ports

import "encoding/json"

// TicketGroupFormatter encodes a server-built asset table without interpreting
// cell values as markup. The use case supplies class-filtered, redacted cells and
// localized headers; adapters must bound the table and final wire description.
type TicketGroupFormatter interface {
	FormatTicketGroupDescription(body string, links []RenderedLink, headers []string, rows [][]string) (json.RawMessage, error)
}
