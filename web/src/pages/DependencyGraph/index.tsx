import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Boxes, Network, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Card, EmptyState } from '../../components/ui'
import type { ScanResult } from '../../lib/types'
import {
  buildIndex,
  blastRadiusGraph,
  EMPTY_SUB,
  explorerGraph,
  findingPathGraph,
  licensePathGraph,
  MAX_NODES,
  toFlow,
  type GraphIndex,
  type SubGraph,
} from '../../lib/dependencyGraphUtils'
import { GraphControlsBar, ModeSwitcher, useLicenseOptions, type Mode } from './GraphControls'

export { DependencyGraphTab }

function DependencyGraphTab({ scan }: { scan: ScanResult | null }) {
  const idx = useMemo(() => (scan ? buildIndex(scan) : null), [scan])
  const [mode, setMode] = useState<Mode>('finding')
  const [vulnIdx, setVulnIdx] = useState(0)
  const [focusId, setFocusId] = useState<string | null>(null)
  const [depth, setDepth] = useState(2)
  const [licId, setLicId] = useState<string | null>(null)

  const licenseOptions = useLicenseOptions(scan, idx)
  const effLic = licId ?? licenseOptions[0]?.value ?? null

  const sub = useMemo<SubGraph>(() => {
    if (!idx || !scan) return EMPTY_SUB
    switch (mode) {
      case 'finding':
        return scan.vulnerabilities[vulnIdx] ? findingPathGraph(idx, scan.vulnerabilities[vulnIdx]) : EMPTY_SUB
      case 'explorer':
        return focusId && idx.meta.has(focusId) ? explorerGraph(idx, focusId, depth) : EMPTY_SUB
      case 'license':
        return effLic && idx.meta.has(effLic) ? licensePathGraph(idx, effLic) : EMPTY_SUB
      case 'blast':
        return focusId && idx.meta.has(focusId) ? blastRadiusGraph(idx, focusId) : EMPTY_SUB
    }
  }, [idx, scan, mode, vulnIdx, focusId, depth, effLic])

  const capped = sub.ids.size > MAX_NODES
  const flow = useMemo(() => (idx && sub.ids.size > 0 && !capped ? toFlow(idx, sub) : null), [idx, sub, capped])

  if (!scan || !idx) {
    return <EmptyState icon={Boxes} title="No scan yet" hint="Run a scan above to explore dependency paths." />
  }

  return (
    <Card bodyClass="p-0">
      <ModeSwitcher mode={mode} setMode={setMode} />
      <GraphControlsBar
        mode={mode}
        scan={scan}
        idx={idx}
        sub={sub}
        vulnIdx={vulnIdx}
        setVulnIdx={setVulnIdx}
        focusId={focusId}
        setFocusId={setFocusId}
        depth={depth}
        setDepth={setDepth}
        licId={licId}
        setLicId={setLicId}
        licenseOptions={licenseOptions}
        effLic={effLic}
      />
      <GraphCanvas
        idx={idx}
        sub={sub}
        flow={flow}
        capped={capped}
        mode={mode}
        hasSelection={mode === 'explorer' || mode === 'blast' ? !!focusId : true}
      />
    </Card>
  )
}

function GraphCanvas({
  idx,
  sub,
  flow,
  capped,
  mode,
  hasSelection,
}: {
  idx: GraphIndex
  sub: SubGraph
  flow: { nodes: Node[]; edges: Edge[] } | null
  capped: boolean
  mode: Mode
  hasSelection: boolean
}) {
  if (capped) {
    return (
      <Centered>
        <Network className="size-7 text-subtlefg" />
        <p className="max-w-md text-sm text-mutedfg">
          This repository contains {idx.totalComponents.toLocaleString()} packages and{' '}
          {idx.totalEdges.toLocaleString()} dependency edges – too large to render at once. Narrow the depth, or use{' '}
          <span className="text-foreground">Finding path</span> / <span className="text-foreground">License path</span>{' '}
          to explore a focused chain.
        </p>
      </Centered>
    )
  }
  if (!hasSelection) {
    return (
      <Centered>
        <Search className="size-7 text-subtlefg" />
        <p className="text-sm text-mutedfg">
          {mode === 'explorer' ? 'Search for a component to see its parents and children.' : 'Search for a component to see its blast radius.'}
        </p>
      </Centered>
    )
  }
  if (!flow || flow.nodes.length === 0) {
    return (
      <Centered>
        <Boxes className="size-7 text-subtlefg" />
        <p className="text-sm text-mutedfg">No dependency relationships recorded for this selection.</p>
      </Centered>
    )
  }
  return (
    <>
      {sub.note && <div className="border-b border-border px-4 py-2 text-xs text-mutedfg">{sub.note}</div>}
      <div className="bg-bg" style={{ height: 540 }}>
        <ReactFlow
          nodes={flow.nodes}
          edges={flow.edges}
          fitView
          minZoom={0.1}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="var(--color-border)" gap={22} />
          <Controls showInteractive={false} />
          {flow.nodes.length > 40 && (
            <MiniMap pannable zoomable style={{ background: 'var(--color-surface)' }} maskColor="rgba(0,0,0,0.5)" />
          )}
        </ReactFlow>
      </div>
    </>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="flex h-[540px] flex-col items-center justify-center gap-3 px-6 text-center">{children}</div>
}
