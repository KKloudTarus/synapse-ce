import { useEffect, useRef, useState } from 'react'
import type { ProjectCodeFinding } from '../../../lib/types'

export function useCodeNavigation({
  findings,
  selectedFinding,
  onSelectFinding,
}: {
  findings: ProjectCodeFinding[]
  selectedFinding: ProjectCodeFinding | null
  onSelectFinding: (finding: ProjectCodeFinding | null) => void
}) {
  const [filesOpen, setFilesOpen] = useState(false)
  const filesButton = useRef<HTMLButtonElement>(null)
  const filesPanel = useRef<HTMLElement>(null)

  // Keyboard navigation for findings [ and ]
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target
      if (target instanceof Element && target.matches('input, textarea, select, [contenteditable=true]')) return
      if (event.key !== '[' && event.key !== ']') return
      if (!findings.length) return
      event.preventDefault()
      const at = selectedFinding ? findings.findIndex((finding) => finding.id === selectedFinding.id) : -1
      onSelectFinding(findings[(at + (event.key === ']' ? 1 : findings.length - 1)) % findings.length])
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [findings, onSelectFinding, selectedFinding])

  // Mobile files panel focus trap
  useEffect(() => {
    if (!filesOpen) return
    filesPanel.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setFilesOpen(false)
        return
      }
      if (event.key !== 'Tab' || !filesPanel.current) return
      const focusable = [...filesPanel.current.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])')]
      if (!focusable.length) return
      const first = focusable[0], last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      filesButton.current?.focus()
    }
  }, [filesOpen])

  return {
    filesOpen,
    setFilesOpen,
    filesButton,
    filesPanel,
  }
}
