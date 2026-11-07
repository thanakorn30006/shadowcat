import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Terminal } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ error, errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#070b14] text-gray-200 flex items-center justify-center p-6 select-text font-mono">
          <div className="max-w-2xl w-full bg-cyber-darker border border-red-500/40 rounded-xl p-8 space-y-6 shadow-2xl shadow-red-950/40">
            <div className="flex items-center gap-3 border-b border-red-500/20 pb-4">
              <div className="p-2.5 rounded-lg bg-red-950/80 border border-red-500/40 text-red-400">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-red-400 tracking-wider uppercase flex items-center gap-2">
                  [SYSTEM FAULT] Runtime Exception Intercepted
                </h1>
                <p className="text-xs text-gray-400 mt-0.5">
                  ShadowSolve defensive runtime prevented complete application crash.
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs text-gray-400 uppercase font-bold flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyber-cyan" /> Exception Diagnostic
              </span>
              <pre className="p-4 rounded-lg bg-black/80 border border-red-500/30 text-red-300 text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                {this.state.error?.toString() || 'Unknown Runtime Error'}
              </pre>
            </div>

            {this.state.errorInfo?.componentStack && (
              <div className="space-y-2">
                <span className="text-xs text-gray-500 uppercase font-bold">Stack Trace Traceback</span>
                <pre className="p-3 rounded-lg bg-black/60 border border-cyber-border text-gray-400 text-[11px] overflow-x-auto max-h-40 leading-normal">
                  {this.state.errorInfo.componentStack}
                </pre>
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-gray-500">
                Memory state safeguarded. Click to restart session.
              </span>
              <button
                onClick={this.handleReset}
                className="px-4 py-2 rounded-lg bg-red-950/80 hover:bg-red-900 border border-red-500/50 text-red-200 text-xs font-bold uppercase tracking-wider flex items-center gap-2 transition-all cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" /> [Reload Suite]
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
