import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  /** Optional custom fallback; otherwise a standard error alert is shown. */
  fallback?: ReactNode
  /** Optional label used in the error message for context. */
  label?: string
}

interface State {
  error: Error | null
}

/**
 * Catches render/lifecycle errors in its subtree and shows a recoverable
 * alert instead of tearing down the entire React tree into a blank page.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('StateTrack UI error:', error, info.componentStack)
  }

  reset = () => this.setState({ error: null })

  render() {
    if (this.state.error) {
      if (this.props.fallback) return this.props.fallback
      return (
        <div className="flex h-full w-full items-center justify-center p-4">
          <div className="max-w-md rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
            <p className="font-semibold">
              Something went wrong{this.props.label ? ` in ${this.props.label}` : ''}.
            </p>
            <p className="mt-1 break-all font-mono text-xs">
              {this.state.error.message}
            </p>
            <button
              onClick={this.reset}
              className="mt-3 rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-red-500"
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
