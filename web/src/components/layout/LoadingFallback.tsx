import { Spinner } from '../ui'

export function LoadingFallback() {
  return (
    <div className="flex h-full items-center justify-center">
      <Spinner label="Loading..." />
    </div>
  )
}
