import type { FC } from 'react'
import {
  LayoutGrid01,
  Package,
  ShieldTick,
  ShieldZap,
  Sliders04,
  SwitchHorizontal01,
  Target04,
  Activity,
} from '@untitledui/icons'
import { lazyTab } from './lazyTab'

// Lazy-loaded so React Flow stays out of the initial bundle (only the Graph tab needs it).
export const DependencyGraphTab = lazyTab(() => import('../DependencyGraph').then((m) => ({ default: m.DependencyGraphTab })))
export const AgentTab = lazyTab(() => import('../AgentTab').then((m) => ({ default: m.AgentTab })))
export const ThreatModelTab = lazyTab(() => import('./ThreatModelTab').then((m) => ({ default: m.ThreatModelTab })))
export const CodeQualityTab = lazyTab(() => import('../CodeQuality/CodeQualityTab').then((m) => ({ default: m.CodeQualityTab })))
export const SLATab = lazyTab(() => import('./SLATab').then((m) => ({ default: m.SLATab })))
export const LicensesTab = lazyTab(() => import('./LicensesTab').then((m) => ({ default: m.LicensesTab })))
export const ComponentsTab = lazyTab(() => import('./ComponentsTab').then((m) => ({ default: m.ComponentsTab })))
export const ReconTab = lazyTab(() => import('./ReconTab').then((m) => ({ default: m.ReconTab })))
export const ScanRunsTab = lazyTab(() => import('./ScanRunsTab').then((m) => ({ default: m.ScanRunsTab })))
export const PurpleCoverageTab = lazyTab(() => import('./PurpleCoverageTab').then((m) => ({ default: m.PurpleCoverageTab })))
export const ChainRehearsalTab = lazyTab(() => import('./ChainRehearsalTab').then((m) => ({ default: m.ChainRehearsalTab })))
export const RiskStoriesTab = lazyTab(() => import('./RiskStoriesTab').then((m) => ({ default: m.RiskStoriesTab })))
export const VulnPostureTab = lazyTab(() => import('./VulnPostureTab').then((m) => ({ default: m.VulnPostureTab })))
export const CredentialsTab = lazyTab(() => import('./CredentialsTab').then((m) => ({ default: m.CredentialsTab })))
export const DetectionsTab = lazyTab(() => import('./DetectionsTab').then((m) => ({ default: m.DetectionsTab })))
export const ImportedFindingsTab = lazyTab(() => import('./ImportedFindingsTab').then((m) => ({ default: m.ImportedFindingsTab })))
export const DataGovernanceTab = lazyTab(() => import('./DataGovernanceTab').then((m) => ({ default: m.DataGovernanceTab })))
export const WriteupDraftsTab = lazyTab(() => import('./WriteupDraftsTab').then((m) => ({ default: m.WriteupDraftsTab })))
export const CloudPostureTab = lazyTab(() => import('./CloudPostureTab').then((m) => ({ default: m.CloudPostureTab })))
export const DASTTab = lazyTab(() => import('./DASTTab').then((m) => ({ default: m.DASTTab })))
export const DetectionProvenanceTab = lazyTab(() => import('./DetectionProvenanceTab').then((m) => ({ default: m.DetectionProvenanceTab })))
export const EvidenceTab = lazyTab(() => import('./EvidenceTab').then((m) => ({ default: m.EvidenceTab })))
export const SettingsTab = lazyTab(() => import('./SettingsTab').then((m) => ({ default: m.SettingsTab })))
export const JudgmentReviewTab = lazyTab(() => import('./ReviewsTab').then((m) => ({ default: m.JudgmentReviewTab })))
export const AssessmentComparisonTab = lazyTab(() => import('./AssessmentComparisonTab').then((m) => ({ default: m.AssessmentComparisonTab })))

export type Tab =
  | 'overview'
  | 'findings'
  | 'imported'

  | 'comparison'
  | 'sla'
  | 'risk-stories'
  | 'vuln-posture'
  | 'components'
  | 'vulns'
  | 'licenses'
  | 'graph'
  | 'scanruns'
  | 'credentials'
  | 'quality'
  | 'threats'
  | 'recon'
  | 'purple'
  | 'rehearsal'
  | 'agent'
  | 'cspm'
  | 'dast'
  | 'detections'
  | 'detection-provenance'
  | 'reviews'
  | 'evidence'
  | 'data-governance'
  | 'writeup-drafts'
  | 'settings'

export interface SubTabDefinition {
  id: Tab
  label: string
  countKey?: 'findings' | 'components' | 'vulns' | 'licenses'
}

export interface TabGroupDefinition {
  id: string
  label: string
  icon: FC<{ className?: string }>
  sub?: SubTabDefinition[]
}

export const TAB_GROUPS: TabGroupDefinition[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: LayoutGrid01,
  },
  {
    id: 'findings',
    label: 'Findings',
    icon: ShieldZap,
    sub: [
      { id: 'findings', label: 'All Findings', countKey: 'findings' },
      { id: 'imported', label: 'Imported' },
      { id: 'risk-stories', label: 'Risk Stories' },
      { id: 'vuln-posture', label: 'Vuln Posture' },
      { id: 'sla', label: 'Remediation SLA' },
    ],
  },
  {
    id: 'comparison',
    label: 'Comparison',
    icon: SwitchHorizontal01,
  },
  {
    id: 'supply-chain',
    label: 'Supply Chain',
    icon: Package,
    sub: [
      { id: 'components', label: 'Packages', countKey: 'components' },
      { id: 'vulns', label: 'Vulnerabilities', countKey: 'vulns' },
      { id: 'licenses', label: 'Licenses', countKey: 'licenses' },
      { id: 'graph', label: 'Dependency Graph' },
      { id: 'scanruns', label: 'Scan Runs' },
    ],
  },
  {
    id: 'offensive',
    label: 'Offensive',
    icon: Target04,
    sub: [
      { id: 'recon', label: 'Recon' },
      { id: 'threats', label: 'Threat Model' },
      { id: 'purple', label: 'Purple Coverage' },
      { id: 'rehearsal', label: 'Chain Rehearsal' },
      { id: 'agent', label: 'Agent' },
      { id: 'cspm', label: 'Cloud Posture' },
      { id: 'dast', label: 'DAST' },
    ],
  },
  {
    id: 'runtime',
    label: 'Runtime',
    icon: Activity,
    sub: [
      { id: 'detections', label: 'Detections' },
      { id: 'detection-provenance', label: 'Provenance' },
    ],
  },
  {
    id: 'governance',
    label: 'Governance',
    icon: ShieldTick,
    sub: [
      { id: 'evidence', label: 'Evidence' },
      { id: 'reviews', label: 'Awaiting Review' },
      { id: 'quality', label: 'Code Quality' },
      { id: 'credentials', label: 'Credentials' },
      { id: 'data-governance', label: 'Data governance' },
      { id: 'writeup-drafts', label: 'Write-up Drafts' },
    ],
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: Sliders04,
  },
]

export function getGroupForTab(tab: Tab): TabGroupDefinition {
  for (const group of TAB_GROUPS) {
    if (group.id === tab && !group.sub) return group
    if (group.sub?.some((s) => s.id === tab)) return group
  }
  return TAB_GROUPS[0]
}

const ALL_TABS: Tab[] = TAB_GROUPS.flatMap((g) => (g.sub ? g.sub.map((s) => s.id) : [g.id as Tab]))

export function isTab(value: string | undefined): value is Tab {
  return Boolean(value) && ALL_TABS.includes(value as Tab)
}

