import type { FC } from 'react'
import { AlertCircle, RefreshCw01 } from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { cx } from '@/utils/cx'

export interface PageErrorProps {
  error: Error | { message: string } | string
  onRetry?: () => void
  className?: string
}

export const PageError: FC<PageErrorProps> = ({ error, onRetry, className }) => {
  const errorMessage =
    typeof error === 'string'
      ? error
      : error?.message || 'An unexpected error occurred'
  const truncatedMessage = errorMessage.slice(0, 200)

  return (
    <div
      data-testid="page-error"
      className={cx(
        'flex flex-col items-center justify-center min-h-[200px] max-w-md mx-auto gap-4 text-center p-6',
        className
      )}
    >
      <div className="flex w-full items-start gap-3 rounded-xl border border-utility-red-200 bg-utility-red-50 p-4 text-left text-sm text-utility-red-700 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-300">
        <AlertCircle className="size-5 shrink-0 text-utility-red-600 dark:text-utility-red-400 mt-0.5" />
        <div className="min-w-0 flex-1 break-words font-medium">
          {truncatedMessage}
        </div>
      </div>

      {onRetry && (
        <Button
          color="primary"
          size="sm"
          iconLeading={RefreshCw01}
          onPress={onRetry}
        >
          Retry
        </Button>
      )}
    </div>
  )
}
