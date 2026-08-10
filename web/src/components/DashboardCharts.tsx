import { cn } from './ui'
import type { DashboardTrendPoint } from '../lib/types'

export type ChartDatum = { key: string; label: string; value: number; color: string }

const CIRCUMFERENCE = 2 * Math.PI * 46

export function DonutChart({ title, centerLabel, data }: { title: string; centerLabel: string; data: ChartDatum[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  let offset = 0
  return (
    <div className="grid min-h-64 items-center gap-5 sm:grid-cols-[minmax(150px,0.7fr)_minmax(200px,1fr)]">
      <figure className="mx-auto size-44" aria-label={`${title}: ${total} total`}>
        <svg viewBox="0 0 120 120" role="img" className="size-full" aria-label={`${title} donut chart`}>
          <title>{title}</title>
          <circle cx="60" cy="60" r="46" fill="none" stroke="var(--color-muted)" strokeWidth="14" />
          {data.map((item) => {
            const length = total ? item.value / total * CIRCUMFERENCE : 0
            const segment = (
              <circle
                key={item.key}
                cx="60"
                cy="60"
                r="46"
                fill="none"
                stroke={item.color}
                strokeWidth="14"
                strokeDasharray={`${length} ${CIRCUMFERENCE - length}`}
                strokeDashoffset={-offset}
                strokeLinecap={item.value === total ? 'round' : 'butt'}
                transform="rotate(-90 60 60)"
              >
                <title>{item.label}: {item.value} ({percentage(item.value, total)}%)</title>
              </circle>
            )
            offset += length
            return segment
          })}
          <text x="60" y="57" textAnchor="middle" className="fill-foreground text-[18px] font-bold tabular-nums">{total}</text>
          <text x="60" y="74" textAnchor="middle" className="fill-mutedfg text-[8px] font-semibold uppercase tracking-wider">{centerLabel}</text>
        </svg>
      </figure>
      <ul className="space-y-3">
        {data.map((item) => (
          <li key={item.key} className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 text-xs">
            <span className="flex min-w-0 items-center gap-2 font-medium text-mutedfg"><span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: item.color }} /><span className="truncate">{item.label}</span></span>
            <span className="font-mono font-semibold tabular-nums text-foreground">{item.value}</span>
            <span className="w-10 text-right font-mono tabular-nums text-subtlefg">{percentage(item.value, total)}%</span>
          </li>
        ))}
        {total === 0 && <li className="text-xs text-subtlefg">No data available.</li>}
      </ul>
    </div>
  )
}

export function HorizontalBarChart({ title, data }: { title: string; data: ChartDatum[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  const max = Math.max(1, ...data.map((item) => item.value))
  return (
    <figure aria-label={title} className="min-h-64 space-y-5 py-2">
      <figcaption className="sr-only">{title}</figcaption>
      {data.map((item) => (
        <div key={item.key} className="grid grid-cols-[5.5rem_minmax(0,1fr)_2.5rem] items-center gap-3 text-xs sm:grid-cols-[7rem_minmax(0,1fr)_3rem]">
          <span className="truncate font-medium text-mutedfg">{item.label}</span>
          <div className="h-3 overflow-hidden rounded-full bg-muted">
            <div className="bar-grow h-full rounded-full" style={{ width: `${item.value / max * 100}%`, backgroundColor: item.color }} />
          </div>
          <span className="text-right font-mono font-semibold tabular-nums">{item.value}</span>
          <span className="col-start-2 -mt-2 text-right font-mono text-[10px] tabular-nums text-subtlefg">{percentage(item.value, total)}%</span>
        </div>
      ))}
      {total === 0 && <p className="text-xs text-subtlefg">No data available.</p>}
    </figure>
  )
}

export function FindingsTrendChart({ points, series }: { points: DashboardTrendPoint[]; series: ChartDatum[] }) {
  const width = 720
  const height = 250
  const left = 38
  const right = 12
  const top = 16
  const bottom = 34
  const plotWidth = width - left - right
  const plotHeight = height - top - bottom
  const max = Math.max(1, ...points.flatMap((point) => series.map((item) => point.counts[item.key] ?? 0)))
  const x = (index: number) => left + (points.length <= 1 ? 0 : index / (points.length - 1) * plotWidth)
  const y = (value: number) => top + plotHeight - value / max * plotHeight
  const labelIndexes = new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])
  const total = points.reduce((sum, point) => sum + series.reduce((row, item) => row + (point.counts[item.key] ?? 0), 0), 0)

  return (
    <div className="min-h-64">
      <div className="mb-3 flex flex-wrap justify-end gap-3">
        {series.map((item) => <span key={item.key} className="inline-flex items-center gap-1.5 text-[10px] font-semibold text-mutedfg"><span className="size-2 rounded-full" style={{ backgroundColor: item.color }} />{item.label}</span>)}
      </div>
      <figure aria-label={`Findings over time: ${total} created findings`} className="overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} role="img" className="h-64 min-w-[36rem] w-full">
          <title>Findings created by day and severity</title>
          {[0, 0.5, 1].map((ratio) => <line key={ratio} x1={left} x2={width - right} y1={top + ratio * plotHeight} y2={top + ratio * plotHeight} stroke="var(--color-border)" strokeWidth="1" />)}
          <text x={left - 8} y={top + 4} textAnchor="end" className="fill-subtlefg text-[9px]">{max}</text>
          <text x={left - 8} y={top + plotHeight + 4} textAnchor="end" className="fill-subtlefg text-[9px]">0</text>
          {series.map((item) => {
            const coordinates = points.map((point, index) => ({ x: x(index), y: y(point.counts[item.key] ?? 0), value: point.counts[item.key] ?? 0, date: point.date }))
            return (
              <g key={item.key}>
                {coordinates.length > 1 && <polyline points={coordinates.map((point) => `${point.x},${point.y}`).join(' ')} fill="none" stroke={item.color} strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />}
                {coordinates.filter((point) => point.value > 0).map((point) => <circle key={`${point.date}-${item.key}`} cx={point.x} cy={point.y} r="4" fill={item.color}><title>{point.date} · {item.label}: {point.value}</title></circle>)}
              </g>
            )
          })}
          {points.map((point, index) => labelIndexes.has(index) && <text key={point.date} x={x(index)} y={height - 8} textAnchor={index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle'} className="fill-subtlefg text-[9px]">{shortDate(point.date)}</text>)}
        </svg>
        <figcaption className={cn('mt-1 text-center text-xs text-subtlefg', total > 0 && 'sr-only')}>{total ? `${total} created findings in range.` : 'No dated findings in this range.'}</figcaption>
      </figure>
    </div>
  )
}

function percentage(value: number, total: number) {
  return total ? Math.round(value / total * 100) : 0
}

function shortDate(value: string) {
  const [, month, day] = value.split('-')
  return `${Number(month)}/${Number(day)}`
}
