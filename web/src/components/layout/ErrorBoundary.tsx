import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props { children: ReactNode; fallback?: ReactNode }
interface State { hasError: boolean; error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }
  static getDerivedStateFromError(error: Error): State { return { hasError: true, error } }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('ErrorBoundary caught:', error, info) }
  reset = () => this.setState({ hasError: false, error: null })
  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? (
        <div className="flex h-full flex-col items-center justify-center gap-4 p-8">
          <p className="text-lg font-medium text-primary">Something went wrong</p>
          <p className="text-sm text-tertiary">{this.state.error?.message}</p>
          <button onClick={this.reset} className="rounded-lg bg-brand-solid px-4 py-2 text-sm font-medium text-white shadow-xs hover:bg-brand-solid_hover">Retry</button>
        </div>
      )
    }
    return this.props.children
  }
}
