// Package report implements TRAZIP's report exporters (prompt maestro §9
// Fase 5, módulo 26): JSON técnico, CSV tabular, HTML autocontenido y PDF
// desde una plantilla controlada — sin herramientas externas (wkhtmltopdf,
// LibreOffice, etc.) y sin una nueva dependencia de terceros para PDF; ver
// pdf.go para un escritor PDF mínimo propio.
//
// Report is deliberately source-agnostic: any TRAZIP module (Monitor,
// Throughput, VoIP, Web Intelligence, PCAP...) builds one from its own
// results without this package needing to know their internal types. The
// caller owns the Summary/Notes text — this package never invents wording,
// per módulo 26 "redacción automática del resumen sin ocultar
// incertidumbre": the honesty has to come from whoever knows the domain.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Meta documents provenance: when the report was built, with which TRAZIP
// version, which dataset versions were in play, and what configuration
// produced the underlying data — prompt maestro §26 "evidencias,
// timestamps, versión de datasets y configuración usada."
type Meta struct {
	GeneratedAt     string            `json:"generatedAt"` // RFC3339
	TrazipVersion   string            `json:"trazipVersion"`
	DatasetVersions map[string]string `json:"datasetVersions,omitempty"`
	Config          map[string]string `json:"config,omitempty"`
}

// Table is one tabular block within a section.
type Table struct {
	Title   string     `json:"title"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
}

// Section is one part of the report: a summary paragraph, optional
// key/value facts, zero or more tables, and explicit notes/caveats — Notes
// is where uncertainty belongs, never smoothed over.
type Section struct {
	Title     string     `json:"title"`
	Summary   string     `json:"summary,omitempty"`
	KeyValues []KeyValue `json:"keyValues,omitempty"`
	Tables    []Table    `json:"tables,omitempty"`
	Notes     []string   `json:"notes,omitempty"`
}

// KeyValue preserves insertion order (a plain map would not) — reports read
// top to bottom the way the caller built them.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Report is the full exportable document.
type Report struct {
	Title    string    `json:"title"`
	Meta     Meta      `json:"meta"`
	Summary  string    `json:"summary"`
	Sections []Section `json:"sections"`
}

// New builds a Report with Meta.GeneratedAt/TrazipVersion filled in.
func New(title, trazipVersion string) Report {
	return Report{
		Title: title,
		Meta: Meta{
			GeneratedAt:   time.Now().Format(time.RFC3339),
			TrazipVersion: trazipVersion,
		},
	}
}

// ToJSON renders the technical, complete JSON form.
func (r Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToCSV renders every table across every section as tabular CSV, with
// section/table titles as comment lines (RFC 4180 doesn't define comments,
// but a leading "#" line is the de-facto convention every spreadsheet tool
// treats as a plain, safely-ignorable cell instead of failing to parse).
func (r Report) ToCSV() []byte {
	var buf bytes.Buffer
	buf.WriteString(csvEscape(r.Title) + "\n")
	buf.WriteString(csvEscape("Generado: "+r.Meta.GeneratedAt+" · TRAZIP "+r.Meta.TrazipVersion) + "\n\n")

	for _, sec := range r.Sections {
		buf.WriteString(csvEscape("# "+sec.Title) + "\n")
		if sec.Summary != "" {
			buf.WriteString(csvEscape(sec.Summary) + "\n")
		}
		for _, kv := range sec.KeyValues {
			buf.WriteString(csvEscape(kv.Key) + "," + csvEscape(kv.Value) + "\n")
		}
		for _, tbl := range sec.Tables {
			buf.WriteString("\n" + csvEscape("## "+tbl.Title) + "\n")
			buf.WriteString(joinCSVRow(tbl.Columns) + "\n")
			for _, row := range tbl.Rows {
				buf.WriteString(joinCSVRow(row) + "\n")
			}
		}
		for _, n := range sec.Notes {
			buf.WriteString(csvEscape("NOTA: "+n) + "\n")
		}
		buf.WriteString("\n")
	}
	return buf.Bytes()
}

func joinCSVRow(cells []string) string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = csvEscape(c)
	}
	return strings.Join(out, ",")
}

func csvEscape(v string) string {
	v = neutralizeCSVFormula(v)
	if strings.ContainsAny(v, ",\"\n") {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

// neutralizeCSVFormula prevents spreadsheet programs from interpreting
// attacker-controlled report fields as formulas when a CSV is opened. The
// apostrophe is the portable spreadsheet convention for forcing text.
func neutralizeCSVFormula(v string) string {
	if v == "" {
		return v
	}
	trimmed := strings.TrimLeft(v, " \t\r\ufeff")
	if strings.HasPrefix(v, "\t") || strings.HasPrefix(v, "\r") ||
		(trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + v
	}
	return v
}

// ToHTML renders a single self-contained HTML file (inline CSS, no external
// assets, no network calls) — safe to open offline and to hand to someone
// else without leaking anything beyond the report's own content.
func (r Report) ToHTML() []byte {
	var b bytes.Buffer
	b.WriteString("<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>")
	b.WriteString(htmlEscape(r.Title))
	b.WriteString("</title><style>")
	b.WriteString(reportCSS)
	b.WriteString("</style></head><body>")
	fmt.Fprintf(&b, "<h1>%s</h1>", htmlEscape(r.Title))
	fmt.Fprintf(&b, "<p class=\"meta\">Generado %s · TRAZIP %s</p>", htmlEscape(r.Meta.GeneratedAt), htmlEscape(r.Meta.TrazipVersion))
	if len(r.Meta.DatasetVersions) > 0 {
		b.WriteString("<p class=\"meta\">Datasets: ")
		first := true
		for k, v := range r.Meta.DatasetVersions {
			if !first {
				b.WriteString(" · ")
			}
			first = false
			fmt.Fprintf(&b, "%s (%s)", htmlEscape(k), htmlEscape(v))
		}
		b.WriteString("</p>")
	}
	if len(r.Meta.Config) > 0 {
		b.WriteString("<p class=\"meta\">Configuración: ")
		first := true
		for k, v := range r.Meta.Config {
			if !first {
				b.WriteString(" · ")
			}
			first = false
			fmt.Fprintf(&b, "%s=%s", htmlEscape(k), htmlEscape(v))
		}
		b.WriteString("</p>")
	}
	if r.Summary != "" {
		fmt.Fprintf(&b, "<p class=\"summary\">%s</p>", htmlEscape(r.Summary))
	}

	for _, sec := range r.Sections {
		fmt.Fprintf(&b, "<h2>%s</h2>", htmlEscape(sec.Title))
		if sec.Summary != "" {
			fmt.Fprintf(&b, "<p>%s</p>", htmlEscape(sec.Summary))
		}
		if len(sec.KeyValues) > 0 {
			b.WriteString("<dl>")
			for _, kv := range sec.KeyValues {
				fmt.Fprintf(&b, "<dt>%s</dt><dd>%s</dd>", htmlEscape(kv.Key), htmlEscape(kv.Value))
			}
			b.WriteString("</dl>")
		}
		for _, tbl := range sec.Tables {
			fmt.Fprintf(&b, "<h3>%s</h3><table><thead><tr>", htmlEscape(tbl.Title))
			for _, c := range tbl.Columns {
				fmt.Fprintf(&b, "<th>%s</th>", htmlEscape(c))
			}
			b.WriteString("</tr></thead><tbody>")
			for _, row := range tbl.Rows {
				b.WriteString("<tr>")
				for _, cell := range row {
					fmt.Fprintf(&b, "<td>%s</td>", htmlEscape(cell))
				}
				b.WriteString("</tr>")
			}
			b.WriteString("</tbody></table>")
		}
		if len(sec.Notes) > 0 {
			b.WriteString("<ul class=\"notes\">")
			for _, n := range sec.Notes {
				fmt.Fprintf(&b, "<li>%s</li>", htmlEscape(n))
			}
			b.WriteString("</ul>")
		}
	}

	b.WriteString("</body></html>")
	return b.Bytes()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

const reportCSS = `
body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:900px;margin:32px auto;padding:0 20px;color:#111;background:#fff;line-height:1.5}
h1{font-size:22px;margin-bottom:4px}
h2{font-size:17px;margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:6px}
h3{font-size:14px;margin-top:18px}
.meta{color:#666;font-size:12px;margin:2px 0}
.summary{background:#f4f7fb;border:1px solid #d7e2f2;border-radius:6px;padding:12px 14px;margin-top:14px}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:13px}
dt{font-weight:600;color:#444}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:8px}
th,td{border:1px solid #ddd;padding:5px 8px;text-align:left}
th{background:#f0f3f8}
.notes{color:#8a5a00;background:#fff8e8;border:1px solid #f0dca0;border-radius:6px;padding:10px 14px;font-size:12.5px;margin-top:10px}
@media (prefers-color-scheme: dark){
  body{background:#0a1226;color:#e6ecf7}
  .summary{background:#0d1a3a;border-color:#1f3766}
  h2{border-color:#26365c}
  th{background:#12203f}
  th,td{border-color:#26365c}
  .notes{background:#2a2107;border-color:#5c4a12;color:#e8c979}
}
`
