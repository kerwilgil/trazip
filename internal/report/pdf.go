package report

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
)

// pdf.go implements a minimal, hand-rolled PDF 1.4 writer — no third-party
// dependency. PDF text layout for the core 14 fonts (Helvetica, Courier)
// requires no font embedding at all, so a controlled report template
// (title, section headers, paragraphs, monospace tables, pagination) is
// achievable in well under what a general-purpose PDF library would pull
// in, and keeps the exact same "motores propios" posture the project
// already applied to SIP/RTP/RTCP (prompt maestro §5.2).
//
// Every line is placed with an absolute text matrix (Tm), not the
// relative-delta Td operator — computing one absolute Y per line up front
// and emitting it directly avoids any cumulative-offset bug entirely,
// which matters far more here than shaving a few bytes off the content
// stream.
//
// Word-wrap for the proportional Helvetica font uses a fixed average
// character-width approximation (0.5×fontSize) rather than real AFM glyph
// widths — good enough for a technical report's body text, not
// pixel-perfect typesetting. Tables use Courier (a fixed-width core font)
// instead, where padding with spaces aligns columns exactly with no width
// table needed at all.

const (
	pageWidth    = 612.0 // US Letter, points
	pageHeight   = 792.0
	marginX      = 50.0
	marginTop    = 742.0
	marginBottom = 50.0
)

type pdfObject struct {
	offset int
}

type pdfBuilder struct {
	buf     bytes.Buffer
	objects []pdfObject
}

func newPDFBuilder() *pdfBuilder {
	b := &pdfBuilder{}
	b.buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	return b
}

// addObject appends one indirect object and returns its object number.
// Object numbers are always sequential from 1 in insertion order — the
// xref table built in finish() relies on that invariant.
func (b *pdfBuilder) addObject(body string) int {
	num := len(b.objects) + 1
	b.objects = append(b.objects, pdfObject{offset: b.buf.Len()})
	fmt.Fprintf(&b.buf, "%d 0 obj\n%s\nendobj\n", num, body)
	return num
}

// reserveObject allocates an object number without writing bytes yet — used
// for /Pages, whose body (the list of page object numbers) isn't known
// until every page has been laid out and given its own number.
func (b *pdfBuilder) reserveObject() int {
	num := len(b.objects) + 1
	b.objects = append(b.objects, pdfObject{})
	return num
}

// fillReserved writes the body for a number previously returned by
// reserveObject, at the current end of the buffer (i.e. after everything
// else). PDF object numbers don't need to appear in the file in numeric
// order — only the xref table's byte offsets, which this records now.
func (b *pdfBuilder) fillReserved(num int, body string) {
	b.objects[num-1] = pdfObject{offset: b.buf.Len()}
	fmt.Fprintf(&b.buf, "%d 0 obj\n%s\nendobj\n", num, body)
}

func (b *pdfBuilder) finish(rootNum int) []byte {
	xrefOffset := b.buf.Len()
	fmt.Fprintf(&b.buf, "xref\n0 %d\n", len(b.objects)+1)
	b.buf.WriteString("0000000000 65535 f \n")
	for _, o := range b.objects {
		fmt.Fprintf(&b.buf, "%010d 00000 n \n", o.offset)
	}
	fmt.Fprintf(&b.buf, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF", len(b.objects)+1, rootNum, xrefOffset)
	return b.buf.Bytes()
}

// pdfEscape escapes the three characters PDF string literals require
// backslash-escaped: backslash itself, and the literal parentheses.
func pdfEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
	return r.Replace(s)
}

// pdfLine is one line of pre-wrapped text to place on a page.
type pdfLine struct {
	text     string
	font     string // "F1" Helvetica, "F2" Helvetica-Bold, "F3" Courier
	size     float64
	gapAfter float64 // extra vertical space below this line, beyond its own height
}

func wrapHelvetica(text string, size, contentWidth float64) []string {
	charWidth := size * 0.5
	maxChars := int(contentWidth / charWidth)
	if maxChars < 10 {
		maxChars = 10
	}
	return wrapWords(text, maxChars)
}

func wrapWords(text string, maxChars int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > maxChars {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	lines = append(lines, cur)
	return lines
}

// renderTableRows formats a Table as fixed-width Courier rows: since
// Courier is monospace, padding each cell to the widest value in its
// column with spaces aligns everything exactly, with no font-metric
// lookup needed at all. Cells are truncated (with an ellipsis) only if a
// single column alone would overflow the page's content width.
func renderTableRows(tbl Table) []string {
	widths := make([]int, len(tbl.Columns))
	for i, c := range tbl.Columns {
		widths[i] = utf8.RuneCountInString(c)
	}
	for _, row := range tbl.Rows {
		for i, cell := range row {
			if i >= len(widths) {
				continue
			}
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	tableContentWidth := pageWidth - 2*marginX
	maxTotal := int(tableContentWidth / (8.5 * 0.6)) // Courier at 8.5pt, ~0.6em/char
	capColumnWidths(widths, maxTotal)

	// format works in runes throughout, not bytes: "…" (the truncation
	// marker below) is a 3-byte UTF-8 rune, and a byte-length comparison
	// against widths[i] (itself a character count, matching Courier's
	// fixed-width columns) would truncate to widths[i]-1 bytes + 3 bytes of
	// "…" — up to 2 bytes OVER widths[i], sending strings.Repeat's pad
	// count negative and panicking. Runes are what the column-width model
	// actually means, so measuring and slicing in runes keeps every
	// produced cell at exactly widths[i] characters.
	format := func(cells []string) string {
		parts := make([]string, len(widths))
		for i := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			runes := []rune(cell)
			switch {
			case len(runes) <= widths[i]:
				// fits as-is
			case widths[i] > 1:
				runes = append(append([]rune{}, runes[:widths[i]-1]...), '…')
			default:
				if widths[i] < 0 {
					widths[i] = 0
				}
				runes = runes[:widths[i]]
			}
			pad := widths[i] - len(runes)
			if pad < 0 {
				pad = 0
			}
			parts[i] = string(runes) + strings.Repeat(" ", pad)
		}
		return strings.TrimRight(strings.Join(parts, "  "), " ")
	}

	out := make([]string, 0, len(tbl.Rows)+1)
	out = append(out, format(tbl.Columns))
	for _, row := range tbl.Rows {
		out = append(out, format(row))
	}
	return out
}

// capColumnWidths shrinks the widest columns (proportionally) until the
// total fits maxTotal, so a table with one very long free-text column
// doesn't blow past the page margins.
func capColumnWidths(widths []int, maxTotal int) {
	total := func() int {
		sum := 2 * (len(widths) - 1) // "  " separators
		for _, w := range widths {
			sum += w
		}
		return sum
	}
	for total() > maxTotal && len(widths) > 0 {
		maxIdx := 0
		for i, w := range widths {
			if w > widths[maxIdx] {
				maxIdx = i
			}
		}
		if widths[maxIdx] <= 4 {
			break // nothing left worth shrinking
		}
		widths[maxIdx]--
	}
}

// buildLines flattens a Report into the linear sequence of styled lines
// that layoutPages will paginate — kept separate from ToPDF so it can be
// unit-tested without touching any PDF byte-format concerns.
func buildLines(r Report) []pdfLine {
	contentWidth := pageWidth - 2*marginX
	var lines []pdfLine
	push := func(text, font string, size, gap float64) {
		lines = append(lines, pdfLine{text: text, font: font, size: size, gapAfter: gap})
	}
	pushWrapped := func(text, font string, size, gap float64) {
		wrapped := wrapHelvetica(text, size, contentWidth)
		for i, l := range wrapped {
			g := 2.0
			if i == len(wrapped)-1 {
				g = gap
			}
			push(l, font, size, g)
		}
	}

	push(r.Title, "F2", 18, 6)
	push(fmt.Sprintf("Generado %s - TRAZIP %s", r.Meta.GeneratedAt, r.Meta.TrazipVersion), "F1", 9, 10)
	if r.Summary != "" {
		pushWrapped(r.Summary, "F1", 10, 16)
	}

	for _, sec := range r.Sections {
		push(sec.Title, "F2", 13, 8)
		if sec.Summary != "" {
			pushWrapped(sec.Summary, "F1", 10, 8)
		}
		for i, kv := range sec.KeyValues {
			g := 2.0
			if i == len(sec.KeyValues)-1 {
				g = 10
			}
			push(fmt.Sprintf("%s: %s", kv.Key, kv.Value), "F1", 10, g)
		}
		for _, tbl := range sec.Tables {
			push(tbl.Title, "F2", 10.5, 4)
			rows := renderTableRows(tbl)
			for i, row := range rows {
				g := 1.5
				if i == len(rows)-1 {
					g = 12
				}
				push(row, "F3", 8.5, g)
			}
		}
		for i, n := range sec.Notes {
			g := 3.0
			if i == len(sec.Notes)-1 {
				g = 14
			}
			pushWrapped("Nota: "+n, "F1", 9, g)
		}
	}
	return lines
}

// ToPDF renders the report as a paginated PDF using only core-14 fonts.
func (r Report) ToPDF() []byte {
	b := newPDFBuilder()
	lines := buildLines(r)

	fontF1 := b.addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	fontF2 := b.addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	fontF3 := b.addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

	pagesNum := b.reserveObject()
	pageNums := layoutPages(b, lines, pagesNum, fontF1, fontF2, fontF3)

	kids := make([]string, len(pageNums))
	for i, n := range pageNums {
		kids[i] = fmt.Sprintf("%d 0 R", n)
	}
	b.fillReserved(pagesNum, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pageNums)))

	catalogNum := b.addObject(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesNum))
	return b.finish(catalogNum)
}

// layoutPages paginates lines across as many pages as needed and returns
// the object numbers of the created /Page objects, in order.
func layoutPages(b *pdfBuilder, lines []pdfLine, pagesNum, fontF1, fontF2, fontF3 int) []int {
	if len(lines) == 0 {
		lines = []pdfLine{{text: "(sin contenido)", font: "F1", size: 10}}
	}
	var pageNums []int
	i := 0
	for i < len(lines) {
		var content bytes.Buffer
		content.WriteString("BT\n")
		y := marginTop
		for i < len(lines) {
			l := lines[i]
			if y < marginBottom {
				break
			}
			fmt.Fprintf(&content, "/%s %.1f Tf\n1 0 0 1 %.1f %.1f Tm\n(%s) Tj\n", l.font, l.size, marginX, y, pdfEscape(l.text))
			y -= l.size + l.gapAfter
			i++
		}
		content.WriteString("ET")

		streamObj := b.addObject(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", content.Len(), content.String()))
		pageBody := fmt.Sprintf(
			"<< /Type /Page /Parent %d 0 R /Resources << /Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >> >> /MediaBox [0 0 %.0f %.0f] /Contents %d 0 R >>",
			pagesNum, fontF1, fontF2, fontF3, pageWidth, pageHeight, streamObj,
		)
		pageNums = append(pageNums, b.addObject(pageBody))
	}
	return pageNums
}
