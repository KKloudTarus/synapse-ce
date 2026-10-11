import { BracketsEllipses } from '@untitledui/icons'
import { Badge } from '../../../components/base/badges/badges'
import { Tooltip, TooltipTrigger } from '../../../components/base/tooltip/tooltip'
import { EmptyState, InfoNote } from '../../../components/ui'
import type { NotificationEventVariable } from '../../../lib/api/notifications'
import { ANY_EVENT } from './shared'

const CLASS_INFO: Record<string, string> = {
  signal: 'Signal: safe for every channel.',
  summary: 'Summary: needs a channel cleared for summaries or details.',
  detail: 'Detail: only channels cleared for full detail receive it.',
}

/** The token a variable inserts: a field of the event payload, in the template language. */
export function variableToken(name: string): string {
  return `{{.${name}}}`
}

/**
 * Lists the variables the selected event exposes; pressing one inserts it at the cursor of the field
 * last focused. Each entry explains itself in a tooltip: description, data class and list cap.
 */
export function VariablePicker({
  eventType,
  variables,
  disabled,
  onInsert,
}: {
  eventType: string
  variables: NotificationEventVariable[]
  disabled?: boolean
  onInsert: (token: string) => void
}) {
  return (
    <section aria-labelledby="template-variables-heading" className="space-y-3">
      <div className="flex items-center gap-1.5">
        <h3 id="template-variables-heading" className="text-sm font-semibold text-primary">
          Variables
        </h3>
        <InfoNote label="About template variables">
          Press a variable to insert it at the cursor. A variable above a channel's data class renders its default or
          nothing on that channel. List variables are capped at the number shown.
        </InfoNote>
      </div>
      {variables.length === 0 ? (
        <EmptyState
          icon={BracketsEllipses}
          title="This event does not expose template variables yet"
          hint={
            eventType === ANY_EVENT
              ? 'A template for any event can only use variables that every event declares, and none are shared yet. Literal text still works.'
              : 'Literal text and functions on literals still work; variables appear here once the event declares them.'
          }
        />
      ) : (
        <ul className="flex flex-wrap gap-2" aria-label="Template variables">
          {variables.map((variable) => (
            <li key={variable.name}>
              <Tooltip
                title={variable.description || variable.name}
                description={`${CLASS_INFO[variable.class] ?? `Class: ${variable.class}.`}${variable.list_cap > 0 ? ` A list of at most ${variable.list_cap} items.` : ''}`}
              >
                <TooltipTrigger
                  isDisabled={disabled}
                  aria-label={`Insert ${variable.name}`}
                  onPress={() => onInsert(variableToken(variable.name))}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-secondary bg-primary px-2.5 py-1.5 text-xs text-primary shadow-xs hover:bg-secondary disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-brand/60"
                >
                  <span className="font-mono">{variable.name}</span>
                  <Badge type="pill-color" size="sm" color={variable.class === 'detail' ? 'error' : variable.class === 'summary' ? 'warning' : 'gray'}>
                    {variable.class}
                  </Badge>
                  {variable.list_cap > 0 && <span className="text-tertiary">≤ {variable.list_cap}</span>}
                </TooltipTrigger>
              </Tooltip>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
