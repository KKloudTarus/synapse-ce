import { CheckCircle2, XCircle } from 'lucide-react'

interface RuleExamplesProps {
  compliant: string
  noncompliant: string
}

export function RuleExamples({ compliant, noncompliant }: RuleExamplesProps) {
  if (!compliant && !noncompliant) return null

  return (
    <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
      {noncompliant && (
        <div className="flex flex-col overflow-hidden rounded-xl border border-danger/30 bg-surface">
          <div className="flex items-center gap-2 border-b border-danger/20 bg-danger/10 px-4 py-2 font-medium text-danger">
            <XCircle className="size-4" />
            <span>Noncompliant</span>
          </div>
          <div className="flex-1 overflow-x-auto p-4">
            <pre className="text-sm">
              <code>{noncompliant}</code>
            </pre>
          </div>
        </div>
      )}

      {compliant && (
        <div className="flex flex-col overflow-hidden rounded-xl border border-success/30 bg-surface">
          <div className="flex items-center gap-2 border-b border-success/20 bg-success/10 px-4 py-2 font-medium text-success">
            <CheckCircle2 className="size-4" />
            <span>Compliant</span>
          </div>
          <div className="flex-1 overflow-x-auto p-4">
            <pre className="text-sm">
              <code>{compliant}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
