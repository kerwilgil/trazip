package monitor

import (
	"fmt"

	"trazip/internal/report"
)

// ToReport builds a module-26 Report from one target's history, optionally
// including a window comparison. This is the module-25→26 bridge: the
// summary/notes text is written here, by the code that actually understands
// what a monitor history means — report.Report itself stays generic and
// never invents domain wording (see internal/report's package doc).
func ToReport(h History, cmp *WindowComparison, trazipVersion string) report.Report {
	r := report.New(fmt.Sprintf("Monitor histórico — %s (%s)", h.Target.Label, h.Target.Address), trazipVersion)
	r.Meta.Config = map[string]string{
		"modo":      string(h.Target.Mode),
		"intervalo": fmt.Sprintf("%d ms", h.Target.IntervalMs),
		"retención": fmt.Sprintf("%d h", h.Target.RetentionHours),
		"creado":    h.Target.CreatedAt,
	}

	total := len(h.Samples)
	lost := 0
	for _, s := range h.Samples {
		if !s.OK {
			lost++
		}
	}
	lossPct := 0.0
	if total > 0 {
		lossPct = round2(float64(lost) / float64(total) * 100)
	}
	r.Summary = fmt.Sprintf(
		"%d muestra(s) registradas para %s (%s). Pérdida general: %.2f%%. %d evento(s) de degradación detectados.",
		total, h.Target.Address, h.Target.Mode, lossPct, len(h.Events),
	)
	if total == 0 {
		r.Summary += " Sin muestras en el rango solicitado — el monitor pudo no haber corrido todavía o el filtro de tiempo excluye todo el historial."
	}

	sampleSection := report.Section{
		Title: "Muestras",
		Tables: []report.Table{{
			Title:   "Historial",
			Columns: []string{"Hora", "Estado", "RTT (ms)", "Pérdida (%)", "Saltos"},
			Rows:    sampleRows(h.Samples),
		}},
	}
	if total > 0 {
		sampleSection.KeyValues = []report.KeyValue{
			{Key: "Total de muestras", Value: fmt.Sprintf("%d", total)},
			{Key: "Pérdida general", Value: fmt.Sprintf("%.2f%%", lossPct)},
		}
	}
	r.Sections = append(r.Sections, sampleSection)

	if len(h.Events) > 0 {
		rows := make([][]string, len(h.Events))
		for i, e := range h.Events {
			rows[i] = []string{e.Time, e.Kind, e.Detail}
		}
		r.Sections = append(r.Sections, report.Section{
			Title:  "Eventos de degradación",
			Tables: []report.Table{{Title: "Eventos", Columns: []string{"Hora", "Tipo", "Detalle"}, Rows: rows}},
			Notes:  []string{"Un evento marca un cambio de estado (entra o sale de degradación) respecto a una línea base móvil — no una alerta externa verificada."},
		})
	}

	if cmp != nil {
		r.Sections = append(r.Sections, report.Section{
			Title: "Comparación de ventanas",
			Summary: fmt.Sprintf(
				"Ventana reciente (%s a %s, %d muestras) vs. ventana anterior (%s a %s, %d muestras).",
				cmp.Recent.From, cmp.Recent.To, cmp.Recent.Samples, cmp.Previous.From, cmp.Previous.To, cmp.Previous.Samples,
			),
			KeyValues: []report.KeyValue{
				{Key: "RTT promedio reciente", Value: fmt.Sprintf("%.2f ms", cmp.Recent.AvgRTTms)},
				{Key: "RTT promedio anterior", Value: fmt.Sprintf("%.2f ms", cmp.Previous.AvgRTTms)},
				{Key: "Delta RTT promedio", Value: fmt.Sprintf("%+.2f ms", cmp.DeltaAvgRTTms)},
				{Key: "Pérdida reciente", Value: fmt.Sprintf("%.2f%%", cmp.Recent.LossPct)},
				{Key: "Pérdida anterior", Value: fmt.Sprintf("%.2f%%", cmp.Previous.LossPct)},
				{Key: "Delta pérdida", Value: fmt.Sprintf("%+.2f%%", cmp.DeltaLossPct)},
			},
			Notes: []string{"Una comparación de ventanas no implica causalidad — solo contrasta dos períodos del mismo target."},
		})
	}

	if total == 0 {
		r.Sections[0].Notes = append(r.Sections[0].Notes, "No hay datos suficientes para una conclusión — no se debe interpretar la ausencia de muestras como \"todo funciona bien\".")
	}

	return r
}

func sampleRows(samples []Sample) [][]string {
	rows := make([][]string, len(samples))
	for i, s := range samples {
		status := "OK"
		if !s.OK {
			status = "perdido"
		}
		rtt := fmt.Sprintf("%.1f", s.RTTms)
		if !s.OK {
			rtt = "—"
		}
		hops := ""
		if s.HopCount > 0 {
			hops = fmt.Sprintf("%d", s.HopCount)
		}
		rows[i] = []string{s.Time, status, rtt, fmt.Sprintf("%.0f", s.LossPct), hops}
	}
	return rows
}
