import { Menu01 } from '@untitledui/icons'
import { lazy, Suspense, useState } from 'react'
import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { ErrorBoundary } from './components/layout/ErrorBoundary'
import { LoadingFallback } from './components/layout/LoadingFallback'
import { MobileSidebar, Sidebar } from './components/layout/Sidebar'
import { Connect } from './pages/Connect'

// --- Lazy-loaded page components ---
const Dashboard = lazy(() => import('./pages/Dashboard/DashboardPage').then(m => ({ default: m.DashboardPage })))
const Engagements = lazy(() => import('./pages/Engagements/EngagementsPage').then(m => ({ default: m.EngagementsPage })))
const NewEngagement = lazy(() => import('./pages/Engagements/NewEngagementPage').then(m => ({ default: m.NewEngagementPage })))
const EngagementDetail = lazy(() => import('./pages/EngagementDetail').then(m => ({ default: m.EngagementDetail })))
const Assets = lazy(() => import('./pages/Assets/Assets').then(m => ({ default: m.Assets })))
const AssetDetail = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetDetail })))
const AssetOverview = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetOverview })))
const AssetComponents = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetComponents })))
const AssetEngagements = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetEngagements })))
const AssetFindings = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetFindings })))
const AssetCoverageView = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetCoverageView })))
const AssetHistory = lazy(() => import('./pages/Assets/AssetDetail').then(m => ({ default: m.AssetHistory })))
const CodeQualityProjects = lazy(() => import('./pages/CodeQuality/CodeQualityProjects').then(m => ({ default: m.CodeQualityProjects })))
const CodeQualityProject = lazy(() => import('./pages/CodeQuality/CodeQualityProject').then(m => ({ default: m.CodeQualityProject })))
const QualityGates = lazy(() => import('./pages/CodeQuality/QualityGates').then(m => ({ default: m.QualityGates })))
const QualityProfiles = lazy(() => import('./pages/CodeQuality/QualityProfiles').then(m => ({ default: m.QualityProfiles })))
const FleetCoverage = lazy(() => import('./pages/Fleet/FleetCoverage').then(m => ({ default: m.FleetCoverage })))
const Rules = lazy(() => import('./pages/Rules/index'))
const RuleDetail = lazy(() => import('./pages/Rules/RuleDetail'))
const Audit = lazy(() => import('./pages/Settings/Audit').then(m => ({ default: m.Audit })))
const Settings = lazy(() => import('./pages/Settings/Settings').then(m => ({ default: m.Settings })))
const SettingsConfig = lazy(() => import('./pages/Settings/SettingsConfig').then(m => ({ default: m.SettingsConfig })))
const AITriageReviews = lazy(() => import('./pages/AITriage/AITriageReviews').then(m => ({ default: m.AITriageReviews })))
const AITriageObservability = lazy(() => import('./pages/AITriage/AITriageObservability').then(m => ({ default: m.AITriageObservability })))
const VulnerabilityIntelligence = lazy(() => import('./pages/VulnerabilityIntelligence').then(m => ({ default: m.VulnerabilityIntelligence })))
const VulnerabilityAdvisoryPage = lazy(() => import('./pages/VulnerabilityIntelligence/VulnIntelAdvisories').then(m => ({ default: m.VulnerabilityAdvisoryPage })))
const Team = lazy(() => import('./pages/Settings/Team').then(m => ({ default: m.Team })))
const ProjectOverviewPage = lazy(() => import('./pages/CodeQuality/ProjectOverviewPage').then(m => ({ default: m.ProjectOverviewPage })))
const ProjectAnalysisPage = lazy(() => import('./pages/CodeQuality/ProjectAnalysisPage').then(m => ({ default: m.ProjectAnalysisPage })))
const ProjectActivityPage = lazy(() => import('./pages/CodeQuality/ProjectActivityPage').then(m => ({ default: m.ProjectActivityPage })))
const SecurityHotspotsPage = lazy(() => import('./pages/CodeQuality/SecurityHotspots').then(m => ({ default: m.SecurityHotspotsPage })))
const ProjectIssuesPage = lazy(() => import('./pages/CodeQuality/ProjectIssues').then(m => ({ default: m.ProjectIssuesPage })))
const ProjectMeasuresPage = lazy(() => import('./pages/CodeQuality/ProjectMeasuresPage').then(m => ({ default: m.ProjectMeasuresPage })))
const ProjectCodePage = lazy(() => import('./pages/CodeQuality/ProjectCodePage').then(m => ({ default: m.ProjectCodePage })))

export default function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  )
}

function Gate() {
  const { phase } = useAuth()
  if (phase !== 'ready') return <Connect />
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="engagements" element={<Engagements />} />
        <Route path="engagements/new" element={<NewEngagement />} />
        <Route path="engagements/:id" element={<EngagementDetail />} />
        <Route path="engagements/:id/:tabSlug" element={<EngagementDetail />} />
        <Route path="assets" element={<Assets />} />
        <Route path="assets/:key" element={<AssetDetail />}>
          <Route index element={<AssetOverview />} />
          <Route path="components" element={<AssetComponents />} />
          <Route path="engagements" element={<AssetEngagements />} />
          <Route path="findings" element={<AssetFindings />} />
          <Route path="coverage" element={<AssetCoverageView />} />
          <Route path="history" element={<AssetHistory />} />
        </Route>
        <Route path="code-quality" element={<CodeQualityProjects />} />
        <Route path="code-quality/gates" element={<QualityGates />} />
        <Route path="code-quality/profiles" element={<QualityProfiles />} />
        <Route path="code-quality/projects/:key" element={<CodeQualityProject />}>
          <Route index element={<ProjectOverviewPage />} />
          <Route path="hotspots" element={<SecurityHotspotsPage />} />
          <Route path="issues" element={<ProjectIssuesPage />} />
          <Route path="code" element={<ProjectCodePage />} />
          <Route path="measures" element={<ProjectMeasuresPage />} />
          <Route path="analysis" element={<ProjectAnalysisPage />} />
          <Route path="activity" element={<ProjectActivityPage />} />
        </Route>
        <Route path="fleet" element={<FleetCoverage />} />
        <Route path="fleet/agents" element={<Navigate to="/fleet" replace />} />
        <Route path="rules" element={<Rules />} />
        <Route path="rules/:key" element={<RuleDetail />} />
        <Route path="settings" element={<Settings />}>
          <Route index element={<Audit />} />
          <Route path="team" element={<Team />} />
          <Route path="config" element={<SettingsConfig />} />
        </Route>
        <Route path="audit" element={<Navigate to="/settings" replace />} />
        <Route path="team" element={<Navigate to="/settings/team" replace />} />
        <Route path="ai-triage/reviews" element={<AITriageReviews />} />
        <Route path="ai-triage/observability" element={<AITriageObservability />} />
        <Route path="vulnerability-intelligence" element={<VulnerabilityIntelligence />} />
        <Route path="vulnerability-intelligence/advisories/:advisoryId" element={<VulnerabilityAdvisoryPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}

function Shell() {
  const [menuOpen, setMenuOpen] = useState(false)
  const location = useLocation()
  return (
    <div className="h-screen overflow-hidden bg-primary md:grid md:grid-cols-[auto_1fr]">
      <Sidebar />
      <MobileSidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="flex min-h-0 min-w-0 flex-col bg-primary md:pt-4">
        {/* Mobile hamburger only */}
        <div className="flex h-14 shrink-0 items-center px-4 md:hidden">
          <button
            type="button"
            onClick={() => setMenuOpen(true)}
            aria-label="Open menu"
            className="inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg text-secondary transition-colors hover:bg-primary_hover hover:text-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
          >
            <Menu01 className="size-5" />
          </button>
        </div>
        <main className="flex-1 overflow-auto bg-secondary-subtle p-4 sm:p-6 xl:p-8 md:rounded-tl-[40px] md:border-t md:border-l md:border-secondary md:shadow-md">
          <ErrorBoundary key={location.pathname}>
            <Suspense fallback={<LoadingFallback />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
