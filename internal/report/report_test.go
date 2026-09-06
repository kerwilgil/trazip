package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func sampleReport() Report {
	r := New("Reporte de prueba", "0.1.0-dev")
	r.Summary = "Resumen general del reporte, con acentos: pérdida, país, configuración."
	r.Meta.DatasetVersions = map[string]string{"GeoLite2-City": "2026-06-01"}
	r.Meta.Config = map[string]string{"target": "8.8.8.8"}
	r.Sections = []Section{
		{
			Title:   "Sección 1",
			Summary: "Un resumen de la sección con texto suficientemente largo como para forzar el ajuste de línea en el exportador PDF, que usa un ancho de carácter aproximado para Helvetica.",
			KeyValues: []KeyValue{
				{Key: "Pérdida", Value: "0%"},
				{Key: "Promedio", Value: "20.1 ms"},
			},
			Tables: []Table{
				{
					Title:   "Muestras",
					Columns: []string{"Hora", "RTT (ms)", "Estado"},
					Rows: [][]string{
						{"10:00:00", "19.5", "OK"},
						{"10:00:05", "20.1", "OK"},
						{"10:00:10", "—", "perdido"},
					},
				},
			},
			Notes: []string{"Sin datasets GeoIP cargados: país/ASN no disponible."},
		},
	}
	return r
}

func TestToJSONRoundTrips(t *testing.T) {
	r := sampleReport()
	body, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Title != r.Title || len(back.Sections) != 1 || len(back.Sections[0].Tables[0].Rows) != 3 {
		t.Errorf("round-tripped report mismatch: %+v", back)
	}
}

func TestToCSVContainsData(t *testing.T) {
	r := sampleReport()
	csv := string(r.ToCSV())
	for _, want := range []string{"Reporte de prueba", "Sección 1", "Muestras", "Hora,RTT (ms),Estado", "19.5", "Sin datasets GeoIP"} {
		if !strings.Contains(csv, want) {
			t.Errorf("CSV missing %q\n--- CSV ---\n%s", want, csv)
		}
	}
}

func TestCSVEscapesCommasAndQuotes(t *testing.T) {
	tbl := Table{Columns: []string{"a"}, Rows: [][]string{{`hello, "world"`}}}
	out := joinCSVRow(tbl.Rows[0])
	if out != `"hello, ""world"""` {
		t.Errorf("joinCSVRow = %q, want a properly quoted/escaped CSV cell", out)
	}
}

func TestCSVNeutralizesSpreadsheetFormulas(t *testing.T) {
	for _, input := range []string{
		`=HYPERLINK("https://example.invalid","x")`,
		"+1+1", "-1+1", "@SUM(A1:A2)", "\t=cmd", "\r=cmd", "  =1+1", "\ufeff=1+1",
	} {
		got := csvEscape(input)
		if !strings.HasPrefix(got, "'") && !strings.HasPrefix(got, `"'`) {
			t.Errorf("csvEscape(%q) = %q, formula was not forced to text", input, got)
		}
	}
}

func TestToHTMLSelfContainedAndEscaped(t *testing.T) {
	r := sampleReport()
	r.Sections[0].Notes = append(r.Sections[0].Notes, "<script>alert(1)</script>")
	html := string(r.ToHTML())

	if !strings.HasPrefix(html, "<!doctype html>") {
		t.Error("expected a doctype at the start")
	}
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") || strings.Contains(html, "<link") || strings.Contains(html, "<script src") {
		t.Error("HTML export must be self-contained: no external assets/links")
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("note text must be HTML-escaped, not injected raw")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the escaped form of the malicious note")
	}
}

func TestToPDFStartsAndEndsCorrectly(t *testing.T) {
	pdf := Report{Title: "x", Meta: Meta{GeneratedAt: "now", TrazipVersion: "0.1"}}.ToPDF()
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Error("expected a %PDF-1.4 header")
	}
	if !bytes.Contains(pdf, []byte("%%EOF")) {
		t.Error("expected an EOF trailer marker")
	}
}

func TestToPDFXrefOffsetsAreByteAccurate(t *testing.T) {
	// The single most important correctness property of a hand-rolled PDF
	// writer: every offset in the xref table must point to the exact byte
	// where "N 0 obj" starts for object N. A single off-by-one here (or
	// anywhere upstream that shifts buffer length after an offset was
	// recorded) produces a PDF that strict readers reject outright.
	pdf := sampleReport().ToPDF()
	verifyXref(t, pdf)
}

func TestToPDFMultiPageXrefStillAccurate(t *testing.T) {
	r := New("Reporte largo", "0.1.0-dev")
	var rows [][]string
	for i := 0; i < 200; i++ {
		rows = append(rows, []string{fmt.Sprintf("10:%02d:00", i%60), "20.0", "OK"})
	}
	r.Sections = []Section{{
		Title:  "Muchas filas",
		Tables: []Table{{Title: "t", Columns: []string{"Hora", "RTT", "Estado"}, Rows: rows}},
	}}
	pdf := r.ToPDF()
	verifyXref(t, pdf)

	// A 200-row table at ~1.5pt line pitch cannot fit on one Letter page —
	// this must have produced more than one /Page object.
	pageCount := bytes.Count(pdf, []byte("/Type /Page /Parent"))
	if pageCount < 2 {
		t.Errorf("expected pagination to kick in for 200 rows, got %d page(s)", pageCount)
	}
}

func TestToPDFEscapesParensAndBackslashes(t *testing.T) {
	r := New("x", "0.1")
	r.Summary = `Ruta: C:\datos\(prueba).pcap`
	pdf := r.ToPDF()
	verifyXref(t, pdf)
	// The raw, unescaped text must never appear literally inside a content
	// stream's string literal, since unescaped '(' / ')' / '\' would
	// desync PDF string-literal parsing.
	if bytes.Contains(pdf, []byte(`(Ruta: C:\datos\(prueba).pcap)`)) {
		t.Error("parentheses/backslashes in report text must be escaped before going into a PDF string literal")
	}
	if !bytes.Contains(pdf, []byte(`C:\\datos\\`)) {
		t.Error("expected the backslash-escaped form in the content stream")
	}
}

func TestRenderTableRowsAlignsColumns(t *testing.T) {
	tbl := Table{
		Columns: []string{"Hora", "RTT"},
		Rows:    [][]string{{"10:00:00", "5"}, {"10:00:05", "123.4"}},
	}
	rows := renderTableRows(tbl)
	if len(rows) != 3 { // header + 2 data rows
		t.Fatalf("renderTableRows returned %d rows, want 3", len(rows))
	}
	// Only the trailing (last) column's padding is trimmed, so total line
	// length legitimately varies row to row — what must stay identical is
	// where the second column actually starts. First column width is
	// max("Hora","10:00:00","10:00:05") = 8, plus the 2-space separator.
	const secondColStart = 8 + 2
	for _, r := range rows {
		if len(r) < secondColStart {
			t.Fatalf("row %q shorter than the first column + separator", r)
		}
		if r[secondColStart-2:secondColStart] != "  " {
			t.Errorf("row %q: expected the 2-space separator right before index %d", r, secondColStart)
		}
	}
}

// TestRenderTableRowsTruncatesWideCellsWithoutPanicking pins down a real
// bug F.0's self test found: a cell needing truncation got sliced by BYTE
// count, then had "…" (a 3-byte UTF-8 rune) appended — up to 2 bytes over
// the intended column width, which sent strings.Repeat's pad count
// negative and panicked. Multi-byte content (any accented text, or a
// column value long enough that capColumnWidths shrinks below its actual
// length) reliably triggers this, so the fixture below forces truncation
// on a UTF-8-heavy cell and asserts the row is produced without panicking
// and its byte length actually respects the table's page-width cap.
func TestRenderTableRowsTruncatesWideCellsWithoutPanicking(t *testing.T) {
	tbl := Table{
		Columns: []string{"Explicación"},
		Rows: [][]string{{
			strings.Repeat("razón observada con acentos y ñ, evidencia detallada — ", 40),
		}},
	}
	rows := renderTableRows(tbl)
	if len(rows) != 2 {
		t.Fatalf("renderTableRows returned %d rows, want 2 (header + 1 data row)", len(rows))
	}
	// tableContentWidth-derived cap (pageWidth - 2*marginX) / (8.5*0.6);
	// asserting well under any plausible page width is enough to prove the
	// column was actually capped, not left at the cell's full length.
	const generousCap = 400
	for _, r := range rows {
		if len(r) > generousCap {
			t.Errorf("row byte length %d exceeds the expected page-width cap (%d) — truncation did not apply", len(r), generousCap)
		}
	}
}

func TestWrapHelveticaRespectsWidth(t *testing.T) {
	long := strings.Repeat("palabra ", 40)
	lines := wrapHelvetica(long, 10, 300)
	if len(lines) < 2 {
		t.Fatalf("expected the long text to wrap across multiple lines, got %d", len(lines))
	}
	maxChars := int(300 / (10 * 0.5))
	for _, l := range lines {
		if len(l) > maxChars {
			t.Errorf("line %q (%d chars) exceeds the computed wrap width %d", l, len(l), maxChars)
		}
	}
}

// verifyXref parses a PDF's trailer/xref table and confirms every recorded
// object offset actually points to that object's "N 0 obj" line.
func verifyXref(t *testing.T, pdf []byte) {
	t.Helper()
	text := string(pdf)

	startxrefIdx := strings.LastIndex(text, "startxref")
	if startxrefIdx < 0 {
		t.Fatal("no startxref found")
	}
	rest := strings.TrimSpace(text[startxrefIdx+len("startxref"):])
	endOfNum := strings.IndexAny(rest, "\n\r")
	if endOfNum < 0 {
		endOfNum = len(rest)
	}
	xrefOffset, err := strconv.Atoi(strings.TrimSpace(rest[:endOfNum]))
	if err != nil {
		t.Fatalf("could not parse startxref offset: %v", err)
	}
	if xrefOffset < 0 || xrefOffset >= len(pdf) {
		t.Fatalf("startxref offset %d out of bounds (file is %d bytes)", xrefOffset, len(pdf))
	}
	if !strings.HasPrefix(text[xrefOffset:], "xref") {
		t.Fatalf("startxref offset %d does not point to the xref table (found %q)", xrefOffset, text[xrefOffset:xrefOffset+10])
	}

	scanner := bufio.NewScanner(strings.NewReader(text[xrefOffset:]))
	scanner.Scan() // "xref"
	scanner.Scan() // "0 N"
	header := strings.Fields(scanner.Text())
	if len(header) != 2 {
		t.Fatalf("unexpected xref subsection header: %q", scanner.Text())
	}
	count, _ := strconv.Atoi(header[1])

	scanner.Scan() // free object 0000000000 65535 f
	checked := 0
	for objNum := 1; objNum < count; objNum++ {
		if !scanner.Scan() {
			t.Fatalf("xref table ended early at object %d of %d", objNum, count-1)
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			t.Fatalf("malformed xref entry for object %d: %q", objNum, scanner.Text())
		}
		offset, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("bad offset for object %d: %v", objNum, err)
		}
		want := fmt.Sprintf("%d 0 obj", objNum)
		if offset < 0 || offset+len(want) > len(pdf) || text[offset:offset+len(want)] != want {
			got := ""
			if offset >= 0 && offset < len(pdf) {
				end := offset + 20
				if end > len(pdf) {
					end = len(pdf)
				}
				got = text[offset:end]
			}
			t.Fatalf("object %d: xref offset %d does not point to %q, found %q", objNum, offset, want, got)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no objects were verified — test itself is broken")
	}
}
