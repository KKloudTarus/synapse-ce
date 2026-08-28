import { useState, useRef, useEffect, type FC } from 'react'
import { useNavigate } from 'react-router-dom'
import { DotsVertical, Eye, Play, Archive, Trash01 } from '@untitledui/icons'
import type { Engagement } from '../../../lib/types'

export interface EngagementRowActionsProps {
  engagement: Engagement
  onStatusChange?: (id: string, newStatus: string) => Promise<void>
  onDelete?: (id: string) => Promise<void>
}

export const EngagementRowActions: FC<EngagementRowActionsProps> = ({
  engagement,
  onStatusChange,
  onDelete,
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  const status = (engagement.status || 'draft').toLowerCase()
  const canStartScan = status === 'draft' || status === 'active'
  const canArchive = status !== 'archived'
  const canDelete = status === 'draft'

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen])

  return (
    <div className="relative inline-block text-left" ref={menuRef}>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation()
          setIsOpen((prev) => !prev)
        }}
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label="Actions for engagement"
        className="flex size-8 items-center justify-center rounded-lg text-tertiary transition-colors hover:bg-secondary hover:text-primary focus:outline-none focus:ring-2 focus:ring-brand/30"
      >
        <DotsVertical className="size-4" aria-hidden="true" />
      </button>

      {isOpen && (
        <div
          role="menu"
          aria-orientation="vertical"
          className="absolute right-0 z-50 mt-1.5 w-44 origin-top-right rounded-xl border border-secondary bg-primary p-1 shadow-lg ring-1 ring-black/5 focus:outline-none animate-in fade-in zoom-in-95 duration-100"
        >
          {/* View Details */}
          <button
            type="button"
            role="menuitem"
            onClick={(e) => {
              e.stopPropagation()
              setIsOpen(false)
              navigate(`/engagements/${engagement.id}`)
            }}
            className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-xs font-medium text-secondary transition-colors hover:bg-secondary hover:text-primary"
          >
            <Eye className="size-3.5 text-tertiary" />
            View Details
          </button>

          {/* Start Scan */}
          {canStartScan && (
            <button
              type="button"
              role="menuitem"
              onClick={(e) => {
                e.stopPropagation()
                setIsOpen(false)
                navigate(`/engagements/${engagement.id}`)
              }}
              className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-xs font-medium text-secondary transition-colors hover:bg-secondary hover:text-primary"
            >
              <Play className="size-3.5 text-utility-brand-600 dark:text-utility-brand-400" />
              Start Scan
            </button>
          )}

          {/* Archive */}
          {canArchive && onStatusChange && (
            <button
              type="button"
              role="menuitem"
              onClick={(e) => {
                e.stopPropagation()
                setIsOpen(false)
                onStatusChange(engagement.id, 'archived')
              }}
              className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-xs font-medium text-secondary transition-colors hover:bg-secondary hover:text-primary"
            >
              <Archive className="size-3.5 text-tertiary" />
              Archive
            </button>
          )}

          {/* Delete */}
          {canDelete && onDelete && (
            <button
              type="button"
              role="menuitem"
              onClick={(e) => {
                e.stopPropagation()
                setIsOpen(false)
                onDelete(engagement.id)
              }}
              className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-xs font-medium text-utility-red-600 transition-colors hover:bg-utility-red-50 hover:text-utility-red-700 dark:text-utility-red-400 dark:hover:bg-utility-red-950/40"
            >
              <Trash01 className="size-3.5" />
              Delete
            </button>
          )}
        </div>
      )}
    </div>
  )
}
