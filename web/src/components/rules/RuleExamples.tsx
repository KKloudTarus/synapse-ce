import { useState } from 'react'
import { Check, CheckCircle, Copy01, XCircle } from '@untitledui/icons'

interface RuleExamplesProps {
  compliant?: string
  noncompliant?: string
}

function ExampleCopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    void navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={copied ? 'Copied' : 'Copy code'}
      title={copied ? 'Copied to clipboard!' : 'Copy code'}
      className="rounded p-1 text-tertiary transition-colors hover:bg-secondary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
    >
      {copied ? <Check className="size-3.5 text-utility-blue-600 dark:text-utility-blue-400" /> : <Copy01 className="size-3.5" />}
    </button>
  )
}

export function RuleExamples({ compliant, noncompliant }: RuleExamplesProps) {
  if (!compliant && !noncompliant) return null

  return (
    <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
      {compliant && (
        <div className="flex flex-col overflow-hidden rounded-lg border border-utility-blue-200 bg-primary dark:border-utility-blue-800 shadow-xs">
          <div className="flex items-center justify-between border-b border-utility-blue-200 bg-utility-blue-50 px-3.5 py-2 text-xs font-semibold text-utility-blue-700 dark:border-utility-blue-800 dark:bg-utility-blue-950/40 dark:text-utility-blue-300">
            <span className="inline-flex items-center gap-1.5">
              <CheckCircle className="size-4" aria-hidden="true" /> Compliant
            </span>
            <ExampleCopyButton text={compliant} />
          </div>
          <div className="flex-1 overflow-x-auto p-3.5">
            <pre className="text-xs font-mono text-primary leading-normal">
              <code>{compliant}</code>
            </pre>
          </div>
        </div>
      )}

      {noncompliant && (
        <div className="flex flex-col overflow-hidden rounded-lg border border-utility-red-200 bg-primary dark:border-utility-red-800 shadow-xs">
          <div className="flex items-center justify-between border-b border-utility-red-200 bg-utility-red-50 px-3.5 py-2 text-xs font-semibold text-utility-red-700 dark:border-utility-red-800 dark:bg-utility-red-950/40 dark:text-utility-red-300">
            <span className="inline-flex items-center gap-1.5">
              <XCircle className="size-4" aria-hidden="true" /> Non-compliant
            </span>
            <ExampleCopyButton text={noncompliant} />
          </div>
          <div className="flex-1 overflow-x-auto p-3.5">
            <pre className="text-xs font-mono text-primary leading-normal">
              <code>{noncompliant}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
