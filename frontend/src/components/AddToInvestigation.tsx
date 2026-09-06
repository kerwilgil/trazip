import { useState } from 'react';
import { investigationCreate, investigationList, type api, type investigation } from '../lib/api';
import { useI18n } from '../lib/i18n';

interface AddToInvestigationProps {
  // The caller owns the actual Snapshot-producing call (diagnose/pcap/
  // monitor/voip) — this component only ever knows an investigation ID and
  // a promise that resolves to the backend's own InvestigationAddResult.
  // It never builds a correlation.Snapshot itself (Phase E: "React NO debe
  // construir correlation.Snapshot manualmente").
  onAdd: (investigationID: string) => Promise<api.InvestigationAddResult>;
  disabled?: boolean;
  disabledReason?: string;
}

type Status = { kind: 'added' | 'existing' | 'error'; message: string };

export default function AddToInvestigation({ onAdd, disabled, disabledReason }: AddToInvestigationProps) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState<investigation.Summary[]>([]);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [newObjective, setNewObjective] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status | null>(null);

  async function openPicker() {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    setCreating(false);
    setStatus(null);
    setLoading(true);
    try {
      const res = await investigationList();
      setList(res.investigations ?? []);
    } catch (e) {
      setStatus({ kind: 'error', message: String(e) });
    } finally {
      setLoading(false);
    }
  }

  async function addTo(id: string, name: string) {
    setBusy(true);
    setStatus(null);
    try {
      const res = await onAdd(id);
      setStatus({
        kind: res.existing ? 'existing' : 'added',
        message: (res.existing ? t('Ya estaba en') : t('Añadido a')) + ' ' + name,
      });
      setOpen(false);
    } catch (e) {
      setStatus({ kind: 'error', message: String(e) });
    } finally {
      setBusy(false);
    }
  }

  async function createAndAdd() {
    const name = newName.trim();
    if (!name) {
      setStatus({ kind: 'error', message: t('El nombre es obligatorio.') });
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      const inv = await investigationCreate(name, newObjective.trim());
      await addTo(inv.id, inv.name);
      setNewName('');
      setNewObjective('');
      setCreating(false);
    } catch (e) {
      setStatus({ kind: 'error', message: String(e) });
      setBusy(false);
    }
  }

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        className="btn ghost"
        style={{ fontSize: 11.5 }}
        disabled={disabled}
        title={disabled ? disabledReason : undefined}
        onClick={openPicker}
      >
        {t('Añadir a investigación')}
      </button>

      {status && !open && (
        <p className={status.kind === 'error' ? 'err' : 'dim'} style={{ fontSize: 11, marginTop: 4 }}>
          {status.kind === 'error' ? status.message : `✓ ${status.message}`}
        </p>
      )}

      {open && (
        <div className="card" style={{ position: 'absolute', zIndex: 20, top: '100%', left: 0, marginTop: 6, width: 280, padding: 12 }}>
          {status?.kind === 'error' && <p className="err" style={{ fontSize: 11.5, marginBottom: 8 }}>{status.message}</p>}

          {!creating && (
            <>
              {loading && <p className="dim" style={{ fontSize: 12 }}>…</p>}
              {!loading && list.length === 0 && (
                <p className="dim" style={{ fontSize: 12 }}>{t('Sin investigaciones todavía.')}</p>
              )}
              {!loading && list.length > 0 && (
                <div className="hop-list" style={{ maxHeight: 220, overflowY: 'auto' }}>
                  {list.map((inv) => (
                    <button
                      key={inv.id}
                      className="hop-row"
                      style={{ width: '100%', textAlign: 'left', cursor: 'pointer', background: 'var(--bg)', border: '1px solid var(--border)' }}
                      disabled={busy}
                      onClick={() => addTo(inv.id, inv.name)}
                    >
                      <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inv.name}</span>
                      <span className="dim" style={{ fontSize: 11, marginLeft: 'auto' }}>{inv.entryCount}</span>
                    </button>
                  ))}
                </div>
              )}
              <button className="btn ghost" style={{ marginTop: 10, width: '100%', fontSize: 11.5 }} onClick={() => setCreating(true)}>
                + {t('Nueva investigación')}
              </button>
            </>
          )}

          {creating && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <input
                className="input"
                placeholder={t('Nombre')}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                maxLength={120}
                autoFocus
              />
              <input
                className="input"
                placeholder={t('Objetivo (opcional)')}
                value={newObjective}
                onChange={(e) => setNewObjective(e.target.value)}
                maxLength={2000}
              />
              <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                <button className="btn ghost" style={{ fontSize: 11.5 }} onClick={() => setCreating(false)}>
                  ←
                </button>
                <button className="btn" style={{ flex: 1, fontSize: 11.5 }} disabled={busy} onClick={createAndAdd}>
                  {t('Crear y añadir')}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
