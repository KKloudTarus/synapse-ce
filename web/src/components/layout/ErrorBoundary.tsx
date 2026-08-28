import { Component, Fragment, type ErrorInfo, type ReactNode } from 'react'

interface Props { children: ReactNode; fallback?: ReactNode }
interface State { hasError: boolean; error: Error | null; resetKey: number }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null, resetKey: 0 }
  static getDerivedStateFromError(error: Error): Partial<State> { return { hasError: true, error } }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('ErrorBoundary caught:', error, info) }
  // Bumping resetKey remounts the subtree, so a retry re-runs mount effects
  // (re-fetches) instead of re-rendering the same failed tree.
  reset = () => this.setState((s) => ({ hasError: false, error: null, resetKey: s.resetKey + 1 }))
  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? (
        <div className="flex h-full flex-col items-center justify-center gap-4 p-8">
          <p className="text-lg font-medium text-primary">Something went wrong</p>
          <p className="text-sm text-tertiary">{this.state.error?.message}</p>
          <button type="button" onClick={this.reset} className="rounded-lg bg-brand-solid px-4 py-2 text-sm font-medium text-white shadow-xs hover:bg-brand-solid_hover">Retry</button>
        </div>
      )
    }
    return <Fragment key={this.state.resetKey}>{this.props.children}</Fragment>
  }
}
