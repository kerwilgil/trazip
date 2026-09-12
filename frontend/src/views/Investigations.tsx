import { useEffect, useState } from 'react';
import {
  backendAvailable,
  investigationList,
  investigationGet,
  investigationCreate,
  investigationUpdateMetadata,
  investigationDelete,
  investigationRemoveEntry,
  investigationUpdateEntryNote,
  investigationExportReport,
  investigationEnrich,
  type investigation,
} from '../lib/api';
import { LEVEL_CLASS, sourceLabel, sortTimeline, formatInstant } from '../lib/investigationHelpers';
import { useI18n } from '../lib/i18n';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

// EntryCount==0 and "no MainFinding because every entry is Info-only" are
// two different, both-honest states — the second must never read as the
// first (E.1-6: an info-only case genuinely has evidence, it just has
// nothing above Info to headline).
function mainFindingText(entryCount: number, mainFinding: string | undefined, t: (s: string) => string): string {
  if (entryCount === 0) return t('Esta investigación todavía no tiene evidencias añadidas.');
  if (mainFinding) return mainFinding;
  return t('Solo hay hallazgos informativos en esta investigación.');
}

function EntryCard({
  entry,
  onRemove,
  onSaveNote,
}: {
  entry: investigation.Entry;
  onRemove: () => void;
  onSaveNote: (note: string) => void;
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState(entry.note ?? '');
  const a = entry.snapshot.assessment;
  const cls = LEVEL_CLASS[a.level] ?? 'ok';

  return (
    <div className="card" style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }} onClick={() => setOpen((v) => !v)}>
        <span className={'pill ' + cls}><span className="dot" /> {t(sourceLabel(entry.snapshot.kind))}</span>
        <span className="dim mono" style={{ fontSize: 11 }}>{formatInstant(entry.snapshot.occurredAt || entry.addedAt)}</span>
        <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {entry.snapshot.subject ? `${entry.snapshot.subject} — ` : ''}{a.conclusion}
        </span>
        <span className="dim" style={{ marginLeft: 'auto', fontSize: 11 }}>{a.confidence}%</span>
        <span className="dim">{open ? '▲' : '▼'}</span>
      </div>

      {open && (
        <div style={{ marginTop: 12 }} onClick={(e) => e.stopPropagation()}>
          {a.evidence && a.evidence.length > 0 && (
            <>
              <h3 style={{ fontSize: 12.5 }}>{t('Evidencias')}</h3>
              <div className="hop-list">
                {a.evidence.map((ev, i) => (
                  <div className="hop-row" key={i}>
                    <span className="hop-host">
                      <span className="mono">{ev.type}: {ev.value}</span>
                      <span className="hop-ip">{ev.source} · {ev.provenance} · {ev.confidence}%{ev.explain ? ' · ' + ev.explain : ''}</span>
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
          {a.counterEvidence && a.counterEvidence.length > 0 && (
            <>
              <h3 style={{ fontSize: 12.5, marginTop: 10 }}>{t('Contraevidencia')}</h3>
              <div className="hop-list">
                {a.counterEvidence.map((ev, i) => (
                  <div className="hop-row" key={i}>
                    <span className="hop-host">
                      <span className="mono">{ev.type}: {ev.value}</span>
                      <span className="hop-ip">{ev.source} · {ev.provenance} · {ev.confidence}%{ev.explain ? ' · ' + ev.explain : ''}</span>
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
          {a.limitations && a.limitations.length > 0 && (
            <>
              <h3 style={{ fontSize: 12.5, marginTop: 10 }}>{t('Limitaciones')}</h3>
              {a.limitations.map((l, i) => (
                <p key={i} className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>⚠ {t(l)}</p>
              ))}
            </>
          )}

          <h3 style={{ fontSize: 12.5, marginTop: 10 }}>{t('Nota del operador')}</h3>
          <textarea
            className="input"
            style={{ width: '100%', minHeight: 50, fontSize: 12.5 }}
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="btn ghost" style={{ fontSize: 11.5 }} onClick={() => onSaveNote(note)}>
              {t('Guardar nota')}
            </button>
            <button className="btn ghost" style={{ fontSize: 11.5, marginLeft: 'auto' }} onClick={onRemove}>
              {t('Eliminar entrada')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Investigations() {
  const { t } = useI18n();
  const [list, setList] = useState<investigation.Summary[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<investigation.Investigation | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newObjective, setNewObjective] = useState('');

  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const [editObjective, setEditObjective] = useState('');

  async function refreshList() {
    const res = await investigationList();
    setList(res.investigations ?? []);
    setWarnings(res.warnings ?? []);
  }

  useEffect(() => {
    if (!backendAvailable()) return;
    refreshList().catch((e) => setError(String(e)));
  }, []);

  async function select(id: string) {
    setSelectedId(id);
    setError(null);
    setEditing(false);
    try {
      const inv = await investigationGet(id);
      setSelected(inv);
    } catch (e) {
      setError(String(e));
      setSelected(null);
    }
  }

  async function createInvestigation() {
    const name = newName.trim();
    if (!name) {
      setError(t('El nombre es obligatorio.'));
      return;
    }
    try {
      const inv = await investigationCreate(name, newObjective.trim());
      setNewName('');
      setNewObjective('');
      setCreating(false);
      await refreshList();
      await select(inv.id);
    } catch (e) {
      setError(String(e));
    }
  }

  function startEditing() {
    if (!selected) return;
    setEditName(selected.name);
    setEditObjective(selected.objective ?? '');
    setEditing(true);
  }

  async function saveMetadata() {
    if (!selected) return;
    const name = editName.trim();
    if (!name) {
      setError(t('El nombre es obligatorio.'));
      return;
    }
    try {
      const updated = await investigationUpdateMetadata(selected.id, name, editObjective.trim());
      setSelected(updated);
      setEditing(false);
      await refreshList();
    } catch (e) {
      setError(String(e));
    }
  }

  async function deleteInvestigation(id: string) {
    if (!confirm(t('¿Eliminar esta investigación? Esta acción no se puede deshacer.'))) return;
    try {
      await investigationDelete(id);
      if (selectedId === id) {
        setSelectedId(null);
        setSelected(null);
      }
      await refreshList();
    } catch (e) {
      setError(String(e));
    }
  }

  async function removeEntry(entryId: string) {
    if (!selected) return;
    if (!confirm(t('¿Eliminar esta entrada de la investigación?'))) return;
    try {
      await investigationRemoveEntry(selected.id, entryId);
      await select(selected.id);
      await refreshList();
    } catch (e) {
      setError(String(e));
    }
  }

  async function saveNote(entryId: string, note: string) {
    if (!selected) return;
    try {
      await investigationUpdateEntryNote(selected.id, entryId, note);
      await select(selected.id);
    } catch (e) {
      setError(String(e));
    }
  }

  async function exportReport(format: string) {
    if (!selected) return;
    try {
      await investigationExportReport(selected.id, format);
    } catch (e) {
      setError(String(e));
    }
  }

  if (!backendAvailable()) {
    return (
      <div className="content-inner">
        <p className="dim">{t(NO_BACKEND)}</p>
      </div>
    );
  }

  const selectedSummary = list.find((s) => s.id === selectedId);
  const timeline = selected ? sortTimeline(selected.entries) : [];

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Investigaciones')}</h2>
        <p className="body-text">
          {t('Un workspace local para agrupar resultados que ya produjiste en Diagnose, PCAP, Monitor y VoIP — nunca ejecuta nada nuevo, solo organiza evidencia existente en una línea de tiempo.')}
        </p>
      </div>

      {error && <div className="note">{error}</div>}
      {warnings.map((w, i) => (
        <div className="note" key={i}>{w}</div>
      ))}

      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start', marginTop: 16 }}>
        <div className="card" style={{ width: 300, flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>{t('Investigaciones')}</h3>
            <button
              className="btn ghost"
              style={{ marginLeft: 'auto', fontSize: 11.5 }}
              onClick={() => setCreating((v) => !v)}
              title={t('Nueva investigación')}
              aria-label={t('Nueva investigación')}
            >
              + {t('Nueva')}
            </button>
          </div>

          {creating && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
              <input className="input" placeholder={t('Nombre')} value={newName} maxLength={120} onChange={(e) => setNewName(e.target.value)} autoFocus />
              <input className="input" placeholder={t('Objetivo (opcional)')} value={newObjective} maxLength={2000} onChange={(e) => setNewObjective(e.target.value)} />
              <button className="btn" style={{ fontSize: 11.5 }} onClick={createInvestigation}>{t('Crear investigación')}</button>
            </div>
          )}

          {list.length === 0 && !creating && (
            <p className="dim" style={{ fontSize: 12, marginTop: 10 }}>{t('Sin investigaciones todavía.')}</p>
          )}

          <div className="hop-list" style={{ marginTop: 10 }}>
            {list.map((inv) => (
              <div
                key={inv.id}
                className="hop-row"
                style={{ cursor: 'pointer', borderColor: inv.id === selectedId ? 'var(--accent)' : undefined }}
                onClick={() => select(inv.id)}
              >
                <span className="hop-host" style={{ minWidth: 0 }}>
                  <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inv.name}</span>
                  <span className="hop-ip">{inv.entryCount} {t('evidencia(s)')} · {formatInstant(inv.updatedAt)}</span>
                </span>
                {inv.entryCount > 0 && <span className={'pill ' + (LEVEL_CLASS[inv.highestLevel] ?? 'ok')}><span className="dot" /></span>}
              </div>
            ))}
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          {!selected && <p className="dim">{t('Selecciona o crea una investigación.')}</p>}

          {selected && (
            <>
              <div className="card">
                {!editing ? (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <h2 style={{ margin: 0 }}>{selected.name}</h2>
                      <button className="btn ghost" style={{ marginLeft: 'auto', fontSize: 11.5 }} onClick={startEditing}>{t('Editar')}</button>
                      <button className="btn ghost" style={{ fontSize: 11.5 }} onClick={() => deleteInvestigation(selected.id)}>{t('Eliminar investigación')}</button>
                    </div>
                    {selected.objective && <p className="body-text" style={{ marginTop: 6 }}>{selected.objective}</p>}
                    <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
                      {t('Creada')}: {formatInstant(selected.createdAt)} · {t('Actualizada')}: {formatInstant(selected.updatedAt)}
                    </p>
                  </>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <input className="input" value={editName} maxLength={120} onChange={(e) => setEditName(e.target.value)} />
                    <input className="input" value={editObjective} maxLength={2000} onChange={(e) => setEditObjective(e.target.value)} />
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button className="btn" style={{ fontSize: 11.5 }} onClick={saveMetadata}>{t('Guardar cambios')}</button>
                      <button className="btn ghost" style={{ fontSize: 11.5 }} onClick={() => setEditing(false)}>✕</button>
                    </div>
                  </div>
                )}

                <div className="grid cols-2" style={{ marginTop: 14 }}>
                  <div>
                    <p className="dim" style={{ fontSize: 12 }}>{t('Cantidad de evidencias')}</p>
                    <p><strong>{selectedSummary?.entryCount ?? selected.entries.length}</strong></p>
                    {selectedSummary?.sourceCounts && (
                      <p className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>
                        {Object.entries(selectedSummary.sourceCounts)
                          .filter(([, n]) => n > 0)
                          .map(([kind, n]) => `${t(sourceLabel(kind))} ${n}`)
                          .join(' · ')}
                      </p>
                    )}
                  </div>
                  <div>
                    <p className="dim" style={{ fontSize: 12 }}>{t('Hallazgo de mayor severidad')}</p>
                    <p>{mainFindingText(selectedSummary?.entryCount ?? selected.entries.length, selectedSummary?.mainFinding, t)}</p>
                  </div>
                </div>

                <div style={{ marginTop: 14 }}>
                  <p className="dim" style={{ fontSize: 12 }}>{t('Exportar investigación')}</p>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {['json', 'csv', 'html', 'pdf'].map((f) => (
                      <button key={f} className="btn ghost" style={{ padding: '3px 10px', fontSize: 11.5 }} onClick={() => exportReport(f)}>
                        {f.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>

                <div style={{ marginTop: 14 }}>
                  <p className="dim" style={{ fontSize: 12 }}>{t('Enriquecer investigación')}</p>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      className="btn"
                      style={{ fontSize: 11.5 }}
                      onClick={async () => {
                        if (!selected) return;
                        try {
                          const result = await investigationEnrich(selected.id);
                          if (result.findings.length === 0) {
                            setError(t('No se pudieron generar hallazgos. Añade evidencias primero.'));
                          } else {
                            setError(null);
                            // Show enrichment result - for now just log and show count
                            console.log('Enrichment result:', result);
                            alert(`${t('Enriquecimiento completado')}: ${result.stats.totalFindings} ${t('hallazgos')}, ${result.stats.totalCorrelations} ${t('correlaciones')}, ${result.stats.totalEvidence} ${t('evidencias')}`);
                          }
                        } catch (e) {
                          setError(String(e));
                        }
                      }}
                    >
                      {t('Enriquecer')}
                    </button>
                    <button
                      className="btn ghost"
                      style={{ fontSize: 11.5 }}
                      onClick={() => {
                        if (!selected) return;
                        investigationEnrich(selected.id).then(r => console.log('Enrichment:', r));
                      }}
                    >
                      {t('Ver en consola')}
                    </button>
                  </div>
                </div>
              </div>

              <h3 style={{ marginTop: 20 }}>{t('Timeline')}</h3>
              {timeline.length === 0 && <p className="dim">{t('Esta investigación todavía no tiene evidencias añadidas.')}</p>}
              {timeline.map((entry) => (
                <EntryCard
                  key={entry.id}
                  entry={entry}
                  onRemove={() => removeEntry(entry.id)}
                  onSaveNote={(note) => saveNote(entry.id, note)}
                />
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
