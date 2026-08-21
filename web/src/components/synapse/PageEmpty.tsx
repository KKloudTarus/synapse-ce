import type { FC } from 'react'
import { FolderSearch } from '@untitledui/icons'
import { Button } from '@/components/base/buttons/button'
import { cx } from '@/utils/cx'

export interface PageEmptyProps {
  title: string
  description: string
  action?: {
    label: string
    onClick: () => void
  }
  icon?: FC<{ className?: string }>
  className?: string
}

export const PageEmpty: FC<PageEmptyProps> = ({
  title,
  description,
  action,
  icon: CustomIcon,
  className,
}) => {
  const IconComponent = CustomIcon || FolderSearch

  return (
    <div
      data-testid="page-empty"
      className={cx(
        'flex flex-col items-center justify-center min-h-[300px] text-center gap-3 p-6',
        className
      )}
    >
      {/* Illustration / Icon placeholder */}
      <div className="size-16 rounded-full bg-secondary text-tertiary flex items-center justify-center shadow-xs">
        <IconComponent className="size-8 text-fg-tertiary" />
      </div>

      <div className="space-y-1">
        <h3 className="text-lg font-semibold text-primary">{title}</h3>
        <p className="text-sm text-secondary max-w-sm mx-auto">{description}</p>
      </div>

      {action && (
        <div className="pt-2">
          <Button color="primary" size="sm" onPress={action.onClick}>
            {action.label}
          </Button>
        </div>
      )}
    </div>
  )
}
