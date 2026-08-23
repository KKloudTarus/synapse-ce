import { useState } from 'react'
import { cn } from '../ui'
import type { DashboardTrendPoint } from '../../lib/types'

export type ChartDatum = { key: string; label: string; value: number; color: string }

export function RadarChart({
  title,
  data,
}: {
  title: string
  data: ChartDatum[]
}) {
  const [hoverKey, setHoverKey] = useState<string | null>(null)
  const total = data.reduce((sum, item) => sum + item.value, 0)
  const maxVal = Math.max(1, ...data.map((d) => d.value))

  const size = 300
  const cx = size / 2
  const cy = size / 2
  const r = 90
  const n = data.length || 5
  const levels = [0.25, 0.5, 0.75, 1.0]

  const angle = (i: number) => -Math.PI / 2 + (i * 2 * Math.PI) / n

  const getPoint = (i: number, radius: number) => {
    const a = angle(i)
    return {
      x: cx + radius * Math.cos(a),
      y: cy + radius * Math.sin(a),
    }
  }

  // Polygon points for data
  const dataPoints = data.map((item, i) => {
    const valRatio = total > 0 ? item.value / maxVal : 0
    const pointR = r * Math.max(0.06, valRatio)
    return {
      ...getPoint(i, pointR),
      item,
      ratio: valRatio,
    }
  })

  const polygonPath = dataPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x},${p.y}`).join(' ') + ' Z'

  return (
    <div className="flex w-full flex-col items-center justify-around gap-4 sm:flex-row sm:gap-6">
      <figure className="relative shrink-0 size-52 sm:size-56" aria-label={`${title}: ${total} total`}>
        <svg viewBox={`0 0 ${size} ${size}`} role="img" className="size-full select-none overflow-visible">
          <title>{title}</title>
          <defs>
            <linearGradient id="radar-gradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-utility-brand-500)" stopOpacity="0.32" />
              <stop offset="100%" stopColor="var(--color-utility-brand-600)" stopOpacity="0.06" />
            </linearGradient>
          </defs>

          {/* Concentric grid polygon rings */}
          {levels.map((lvl) => {
            const lvlPoints = Array.from({ length: n }, (_, i) => getPoint(i, r * lvl))
            const path = lvlPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x},${p.y}`).join(' ') + ' Z'
            return (
              <path
                key={lvl}
                d={path}
                fill="none"
                stroke="var(--color-border-secondary)"
                strokeWidth="1"
                strokeDasharray={lvl === 1 ? undefined : '2 2'}
              />
            )
          })}

          {/* Radial axis lines from center */}
          {Array.from({ length: n }, (_, i) => {
            const end = getPoint(i, r)
            return (
              <line
                key={`axis-${i}`}
                x1={cx}
                y1={cy}
                x2={end.x}
                y2={end.y}
                stroke="var(--color-border-secondary)"
                strokeWidth="1"
              />
            )
          })}

          {/* Filled radar area */}
          <path
            d={polygonPath}
            fill="url(#radar-gradient)"
            stroke="var(--color-utility-brand-600)"
            strokeWidth="2"
            strokeLinejoin="round"
            className="transition-all duration-300"
          />

          {/* Data point dots */}
          {dataPoints.map((p) => (
            <g key={`dot-${p.item.key}`}>
              <circle
                cx={p.x}
                cy={p.y}
                r={hoverKey === p.item.key ? 5.5 : 4}
                fill={p.item.color}
                stroke="var(--color-bg-primary)"
                strokeWidth="2"
                className="transition-all duration-150 cursor-pointer shadow-sm"
                onMouseEnter={() => setHoverKey(p.item.key)}
                onMouseLeave={() => setHoverKey(null)}
              >
                <title>
                  {p.item.label}: {p.item.value} ({percentage(p.item.value, total)}%)
                </title>
              </circle>
            </g>
          ))}

          {/* Outer Vertex Labels */}
          {data.map((item, i) => {
            const a = angle(i)
            const labelR = r + 24
            const lx = cx + labelR * Math.cos(a)
            const ly = cy + labelR * Math.sin(a)

            let textAnchor: 'start' | 'middle' | 'end' = 'middle'
            if (Math.cos(a) > 0.3) textAnchor = 'start'
            else if (Math.cos(a) < -0.3) textAnchor = 'end'

            return (
              <text
                key={`lbl-${item.key}`}
                x={lx}
                y={ly + 4}
                textAnchor={textAnchor}
                className={cn(
                  'fill-current text-[11px] font-medium transition-colors',
                  hoverKey === item.key ? 'text-primary font-semibold' : 'text-tertiary',
                )}
              >
                {item.label}
              </text>
            )
          })}
        </svg>
      </figure>

      {/* Legend list matching Untitled UI */}
      <ul className="w-full sm:w-auto sm:min-w-[190px] sm:max-w-[220px] space-y-2">
        {data.map((item) => (
          <li
            key={item.key}
            className={cn(
              'grid grid-cols-[minmax(0,1fr)_2.5rem_2.5rem] items-center gap-2 rounded-md px-2 py-1 text-xs transition-colors cursor-pointer',
              hoverKey === item.key ? 'bg-secondary' : 'hover:bg-secondary/60',
            )}
            onMouseEnter={() => setHoverKey(item.key)}
            onMouseLeave={() => setHoverKey(null)}
          >
            <span className="flex min-w-0 items-center gap-2.5 font-medium text-secondary">
              <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="truncate">{item.label}</span>
            </span>
            <span className="text-right font-mono font-semibold tabular-nums text-primary">{item.value}</span>
            <span className="text-right font-mono tabular-nums text-tertiary">{percentage(item.value, total)}%</span>
          </li>
        ))}
        {total === 0 && <li className="text-xs text-tertiary">No posture data available.</li>}
      </ul>
    </div>
  )
}

export function DonutChart({ title, centerLabel, data }: { title: string; centerLabel: string; data: ChartDatum[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  const CIRCUMFERENCE_INNER = 2 * Math.PI * 44
  let offset = 0
  return (
    <div className="flex w-full flex-col items-center justify-around gap-4 sm:flex-row sm:gap-6">
      <figure className="relative shrink-0 size-44 sm:size-48" aria-label={`${title}: ${total} total`}>
        <svg viewBox="0 0 120 120" role="img" className="size-full" aria-label={`${title} donut chart`}>
          <title>{title}</title>
          <circle cx="60" cy="60" r="44" fill="none" stroke="var(--color-border-secondary)" strokeWidth="12" />
          {data.map((item) => {
            const length = total ? (item.value / total) * CIRCUMFERENCE_INNER : 0
            const segment = (
              <circle
                key={item.key}
                cx="60"
                cy="60"
                r="44"
                fill="none"
                stroke={item.color}
                strokeWidth="12"
                strokeDasharray={`${length} ${CIRCUMFERENCE_INNER - length}`}
                strokeDashoffset={-offset}
                strokeLinecap={item.value === total ? 'round' : 'butt'}
                transform="rotate(-90 60 60)"
              >
                <title>
                  {item.label}: {item.value} ({percentage(item.value, total)}%)
                </title>
              </circle>
            )
            offset += length
            return segment
          })}
          <text x="60" y="56" textAnchor="middle" className="fill-current text-[20px] font-bold tabular-nums text-primary">
            {total}
          </text>
          <text x="60" y="73" textAnchor="middle" className="fill-current text-[9px] font-semibold uppercase tracking-wider text-tertiary">
            {centerLabel}
          </text>
        </svg>
      </figure>
      <ul className="w-full sm:w-auto sm:min-w-[190px] sm:max-w-[220px] space-y-2">
        {data.map((item) => (
          <li key={item.key} className="grid grid-cols-[minmax(0,1fr)_2.5rem_2.5rem] items-center gap-2 rounded-md px-2 py-1 text-xs transition-colors hover:bg-secondary/60">
            <span className="flex min-w-0 items-center gap-2.5 font-medium text-secondary">
              <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="truncate">{item.label}</span>
            </span>
            <span className="text-right font-mono font-semibold tabular-nums text-primary">{item.value}</span>
            <span className="text-right font-mono tabular-nums text-tertiary">{percentage(item.value, total)}%</span>
          </li>
        ))}
        {total === 0 && <li className="text-xs text-tertiary">No data available.</li>}
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
          <span className="truncate font-medium text-secondary">{item.label}</span>
          <div className="h-3 overflow-hidden rounded-full bg-secondary">
            <div className="bar-grow h-full rounded-full" style={{ width: `${(item.value / max) * 100}%`, backgroundColor: item.color }} />
          </div>
          <span className="text-right font-mono font-semibold tabular-nums text-primary">{item.value}</span>
          <span className="col-start-2 -mt-2 text-right font-mono text-[10px] tabular-nums text-tertiary">{percentage(item.value, total)}%</span>
        </div>
      ))}
      {total === 0 && <p className="text-xs text-tertiary">No data available.</p>}
    </figure>
  )
}

export function FindingsTrendChart({ points, series }: { points: DashboardTrendPoint[]; series: ChartDatum[] }) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null)

  const width = 840
  const height = 260
  const left = 36
  const right = 16
  const top = 16
  const bottom = 32
  const plotWidth = width - left - right
  const plotHeight = height - top - bottom

  const maxVal = Math.max(1, ...points.flatMap((point) => series.map((item) => point.counts[item.key] ?? 0)))
  // Nice round max for grid ticks
  const yTicks = [0, 0.25, 0.5, 0.75, 1]

  const x = (index: number) => left + (points.length <= 1 ? 0 : (index / (points.length - 1)) * plotWidth)
  const y = (value: number) => top + plotHeight - (value / maxVal) * plotHeight

  const total = points.reduce(
    (sum, point) => sum + series.reduce((row, item) => row + (point.counts[item.key] ?? 0), 0),
    0,
  )

  // Determine x-axis label indices (e.g. 5-7 labels max)
  const step = Math.max(1, Math.floor((points.length - 1) / 5))
  const labelIndexes = new Set<number>()
  for (let i = 0; i < points.length; i += step) {
    labelIndexes.add(i)
  }
  if (points.length > 0) labelIndexes.add(points.length - 1)

  const activePoint = hoverIndex !== null && points[hoverIndex] ? points[hoverIndex] : null

  return (
    <div className="relative flex flex-col">
      {/* Legend Row matching Untitled UI */}
      <div className="mb-4 flex flex-wrap items-center justify-end gap-4">
        {series.map((item) => (
          <div key={item.key} className="inline-flex items-center gap-2 text-xs font-medium text-secondary">
            <span
              className="size-2.5 rounded-full ring-2 ring-transparent transition-transform"
              style={{ backgroundColor: item.color }}
            />
            <span>{item.label}</span>
          </div>
        ))}
      </div>

      <figure aria-label={`Findings over time: ${total} created findings`} className="relative overflow-x-auto">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          className="h-64 min-w-[36rem] w-full select-none"
          onMouseLeave={() => setHoverIndex(null)}
        >
          <title>Findings created by day and severity</title>
          <defs>
            {series.map((item) => (
              <linearGradient key={`grad-${item.key}`} id={`grad-${item.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={item.color} stopOpacity="0.22" />
                <stop offset="100%" stopColor={item.color} stopOpacity="0.0" />
              </linearGradient>
            ))}
          </defs>

          {/* Horizontal Grid lines & Y-axis labels */}
          {yTicks.map((ratio) => {
            const yPos = top + (1 - ratio) * plotHeight
            const val = Math.round(ratio * maxVal)
            return (
              <g key={ratio}>
                <line
                  x1={left}
                  x2={width - right}
                  y1={yPos}
                  y2={yPos}
                  stroke="var(--color-border-secondary)"
                  strokeWidth="1"
                  strokeDasharray={ratio === 0 ? undefined : '3 3'}
                />
                <text
                  x={left - 8}
                  y={yPos + 3.5}
                  textAnchor="end"
                  className="fill-current text-[10px] tabular-nums font-mono text-tertiary"
                >
                  {val}
                </text>
              </g>
            )
          })}

          {/* Smooth area gradients */}
          {series.map((item) => {
            const coords = points.map((point, index) => ({
              x: x(index),
              y: y(point.counts[item.key] ?? 0),
            }))
            const areaPath = createSmoothAreaPath(coords, top + plotHeight)
            return <path key={`area-${item.key}`} d={areaPath} fill={`url(#grad-${item.key})`} />
          })}

          {/* Smooth stroke curves */}
          {series.map((item) => {
            const coords = points.map((point, index) => ({
              x: x(index),
              y: y(point.counts[item.key] ?? 0),
            }))
            const linePath = createSmoothPath(coords)
            return (
              <path
                key={`line-${item.key}`}
                d={linePath}
                fill="none"
                stroke={item.color}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            )
          })}

          {/* Active / Hover column crosshair & highlight dots */}
          {hoverIndex !== null && activePoint && (
            <g>
              <line
                x1={x(hoverIndex)}
                x2={x(hoverIndex)}
                y1={top}
                y2={top + plotHeight}
                stroke="var(--color-border-primary)"
                strokeWidth="1.5"
                strokeDasharray="2 2"
              />
              {series.map((item) => {
                const val = activePoint.counts[item.key] ?? 0
                const cxPos = x(hoverIndex)
                const cyPos = y(val)
                return (
                  <g key={`dot-${item.key}`}>
                    <circle
                      cx={cxPos}
                      cy={cyPos}
                      r="4.5"
                      fill={item.color}
                      stroke="var(--color-bg-primary)"
                      strokeWidth="2"
                      className="shadow-sm"
                    />
                  </g>
                )
              })}
            </g>
          )}

          {/* Invisible hover interaction hit areas */}
          {points.map((_, index) => {
            const colWidth = points.length <= 1 ? plotWidth : plotWidth / (points.length - 1)
            const colX = x(index) - colWidth / 2
            return (
              <rect
                key={index}
                x={Math.max(left, colX)}
                y={top}
                width={colWidth}
                height={plotHeight}
                fill="transparent"
                className="cursor-crosshair"
                onMouseEnter={() => setHoverIndex(index)}
              />
            )
          })}

          {/* X-axis date labels */}
          {points.map((point, index) => {
            if (!labelIndexes.has(index)) return null
            return (
              <text
                key={point.date}
                x={x(index)}
                y={height - 8}
                textAnchor={index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle'}
                className="fill-current text-[11px] font-medium text-tertiary"
              >
                {shortDate(point.date)}
              </text>
            )
          })}
        </svg>

        {/* Floating Tooltip card on hover */}
        {hoverIndex !== null && activePoint && (
          <div
            className="pointer-events-none absolute z-10 -translate-x-1/2 rounded-lg border border-secondary bg-primary p-3 shadow-lg transition-all"
            style={{
              left: `${(x(hoverIndex) / width) * 100}%`,
              top: '12px',
            }}
          >
            <p className="text-xs font-semibold text-primary">{activePoint.date}</p>
            <div className="mt-1.5 space-y-1">
              {series.map((item) => {
                const count = activePoint.counts[item.key] ?? 0
                return (
                  <div key={item.key} className="flex items-center justify-between gap-4 text-[11px]">
                    <span className="flex items-center gap-1.5 text-secondary">
                      <span className="size-2 rounded-full" style={{ backgroundColor: item.color }} />
                      {item.label}
                    </span>
                    <span className="font-mono font-semibold tabular-nums text-primary">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        <figcaption className={cn('mt-1 text-center text-xs text-tertiary', total > 0 && 'sr-only')}>
          {total ? `${total} created findings in range.` : 'No dated findings in this range.'}
        </figcaption>
      </figure>
    </div>
  )
}

function createSmoothPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return ''
  if (points.length === 1) return `M ${points[0].x},${points[0].y}`
  if (points.length === 2) {
    return `M ${points[0].x},${points[0].y} L ${points[1].x},${points[1].y}`
  }

  let d = `M ${points[0].x},${points[0].y}`
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[Math.max(0, i - 1)]
    const p1 = points[i]
    const p2 = points[i + 1]
    const p3 = points[Math.min(points.length - 1, i + 2)]

    const cp1x = p1.x + (p2.x - p0.x) / 6
    const cp1y = p1.y + (p2.y - p0.y) / 6
    const cp2x = p2.x - (p3.x - p1.x) / 6
    const cp2y = p2.y - (p3.y - p1.y) / 6

    d += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p2.x},${p2.y}`
  }
  return d
}

function createSmoothAreaPath(points: { x: number; y: number }[], baseY: number): string {
  if (points.length === 0) return ''
  const linePath = createSmoothPath(points)
  const last = points[points.length - 1]
  const first = points[0]
  return `${linePath} L ${last.x},${baseY} L ${first.x},${baseY} Z`
}

function percentage(value: number, total: number) {
  return total ? Math.round((value / total) * 100) : 0
}

function shortDate(value: string) {
  const parts = value.split('-')
  if (parts.length >= 3) {
    const [, month, day] = parts
    return `${Number(month)}/${Number(day)}`
  }
  return value
}
