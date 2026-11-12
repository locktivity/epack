package simulate

import (
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// Pager answers one list as the vendor pages it. size, when above zero,
// replaces the pager's own page size. A pager answers at least one page,
// empty for no items. One with no parameter to name the next page, such as
// a LinkHeader with no Cursor, answers in one page whatever the size, as a
// list the vendor never pages does.
type Pager interface {
	Pages(first string, items []any, size int) []collectortest.Response
}

// NextLink pages a list in a body that holds the items and, on each page
// but the last, the next page's URL at Next, as Microsoft Graph does with
// value and @odata.nextLink, or Okta with value and _links/next/href. Next
// is a path of field names joined by /. The next URL adds Token, an opaque
// token, to the first.
type NextLink struct {
	Items, Next, Token string
	Size               int
	// Envelope holds fields every page carries, such as @odata.context.
	Envelope map[string]any
}

// Pages answers the list at first.
func (p NextLink) Pages(first string, items []any, size int) []collectortest.Response {
	var out []collectortest.Response
	at := exactly(first)
	for _, page := range split(items, pick(size, p.Size), p.Token) {
		body := maps.Clone(p.Envelope)
		if body == nil {
			body = map[string]any{}
		}
		body[p.Items] = page.items
		r := collectortest.Response{URL: at}
		if page.more {
			at = withParam(first, p.Token, token(first, page.end))
			setPath(body, p.Next, at)
		}
		r.Body = JSON(body)
		out = append(out, r)
	}
	return out
}

// LinkHeader pages a list whose body is the bare list, with the next page's
// URL in a Link header, as Okta and GitHub do. Each page also carries a
// self link, which Okta sends as a Link header of its own. The next URL
// adds Cursor to the first, set to CursorOf the page's last item, or an
// opaque token when CursorOf is nil.
type LinkHeader struct {
	Cursor   string
	Size     int
	CursorOf func(item any) string
}

// Pages answers the list at first.
func (p LinkHeader) Pages(first string, items []any, size int) []collectortest.Response {
	var out []collectortest.Response
	at := exactly(first)
	for _, page := range split(items, pick(size, p.Size), p.Cursor) {
		self := strings.TrimSuffix(at, "?")
		r := collectortest.Response{URL: at, Body: JSON(page.items), Header: http.Header{"Link": {"<" + self + `>; rel="self"`}}}
		if page.more {
			cursor := token(first, page.end)
			if p.CursorOf != nil {
				cursor = p.CursorOf(page.items[len(page.items)-1])
			}
			at = withParam(first, p.Cursor, cursor)
			r.Header.Add("Link", "<"+at+`>; rel="next"`)
		}
		out = append(out, r)
	}
	return out
}

// Cursor pages a list in a body that holds the items and the next page's
// cursor at Next, a path of field names joined by /, such as
// response_metadata/next_cursor, which is empty on the last page. The next
// request adds Param, set to the cursor, to the first.
type Cursor struct {
	Items, Next, Param string
	Size               int
}

// Pages answers the list at first.
func (p Cursor) Pages(first string, items []any, size int) []collectortest.Response {
	var out []collectortest.Response
	at := exactly(first)
	for _, page := range split(items, pick(size, p.Size), p.Param) {
		body := map[string]any{p.Items: page.items}
		next := ""
		if page.more {
			next = token(first, page.end)
		}
		setPath(body, p.Next, next)
		out = append(out, collectortest.Response{URL: at, Body: JSON(body)})
		at = withParam(first, p.Param, next)
	}
	return out
}

// Offset pages a list by a number in Param: the offset of the page's first
// item, or the page's number counting from First when ByPage is set. A page
// with Size items says nothing of what follows, so the client asks again,
// and a list that fills its last page ends with an empty one. Items is the
// field that holds the items, or empty for a bare list.
type Offset struct {
	Items, Param string
	Size, First  int
	ByPage       bool
}

// Pages answers the list at first. The first page is the request without
// Param.
func (p Offset) Pages(first string, items []any, size int) []collectortest.Response {
	size = pick(size, p.Size)
	pages := split(items, size, p.Param)
	if p.Param != "" && size > 0 && len(items) > 0 && len(items)%size == 0 {
		pages = append(pages, page{items: []any{}})
	}
	var out []collectortest.Response
	at := exactly(first)
	for i, page := range pages {
		var body any = page.items
		if p.Items != "" {
			body = map[string]any{p.Items: page.items}
		}
		out = append(out, collectortest.Response{URL: at, Body: JSON(body)})
		n := (i + 1) * size
		if p.ByPage {
			n = p.First + i + 1
		}
		at = withParam(first, p.Param, strconv.Itoa(n))
	}
	return out
}

type page struct {
	items []any
	end   int
	more  bool
}

// split cuts items into pages of size, or one page when size is not above
// zero or no parameter names the next page.
func split(items []any, size int, param string) []page {
	if param == "" || size <= 0 || len(items) <= size {
		return []page{{items: items, end: len(items)}}
	}
	var out []page
	for start := 0; start < len(items); start += size {
		end := min(start+size, len(items))
		out = append(out, page{items: items[start:end], end: end, more: end < len(items)})
	}
	return out
}

func pick(override, own int) int {
	if override > 0 {
		return override
	}
	return own
}

// token is an opaque, URL-safe page token for the items before end.
func token(first string, end int) string {
	return base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%s:%d", first, end))
}

// setPath sets the field at path, copying each map on the way, which may
// be shared with an envelope and the other pages.
func setPath(m map[string]any, path string, value any) {
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		next, _ := m[part].(map[string]any)
		next = maps.Clone(next)
		if next == nil {
			next = map[string]any{}
		}
		m[part] = next
		m = next
	}
	m[parts[len(parts)-1]] = value
}
