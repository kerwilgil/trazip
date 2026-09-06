import { useRef, useState } from 'react';

export default function RtpStreamPlayer({ source, label }: { source: string | null; label: string }) {
  const ref = useRef<HTMLAudioElement>(null);
  const [error, setError] = useState<string | null>(null);
  if (!source) return null;
  async function play() { try { await ref.current?.play(); setError(null); } catch { setError('El WebView bloqueó la reproducción. Usa el control de audio o vuelve a intentarlo.'); } }
  return <div><button className="btn ghost" onClick={() => void play()}>▶ Reproducir preparado</button><audio ref={ref} controls preload="metadata" aria-label={label} style={{ width: '100%', marginTop: 8 }} src={source} />{error && <p className="warn" role="status">{error}</p>}</div>;
}
