import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useI18n, type Translate } from '../lib/i18n';

interface Props {
  children: ReactNode;
  t: Translate;
}

interface State {
  error: Error | null;
}

// Without this, any uncaught render exception unmounts the whole React tree
// silently — what's left visible is main.go's window BackgroundColour (dark
// navy), which reads as "the app crashed to a blank blue screen" with zero
// diagnostic info. This turns that into a visible, recoverable error card.
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[TRAZIP] Error no controlado en la interfaz:', error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="content-inner">
        <div className="card pad-lg" style={{ marginTop: 24 }}>
            <h3 style={{ color: 'var(--danger, #e5484d)' }}>{this.props.t('Ocurrió un error inesperado en esta vista')}</h3>
          <p className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {this.props.t('La interfaz encontró una excepción no controlada y se detuvo para evitar mostrar datos inconsistentes. El resto de la app sigue funcionando: cambia de pestaña o vuelve a intentarlo.')}
          </p>
          <pre className="mono" style={{ fontSize: 11.5, marginTop: 10, whiteSpace: 'pre-wrap', color: 'var(--text-faint)' }}>
            {error.message}
          </pre>
          <button className="btn ghost" style={{ marginTop: 10 }} onClick={() => this.setState({ error: null })}>
            {this.props.t('Reintentar')}
          </button>
        </div>
      </div>
    );
  }
}

export function LocalizedErrorBoundary({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  return <ErrorBoundary t={t}>{children}</ErrorBoundary>;
}
