import { useState } from 'react'
import { Navigate, Outlet, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { MobileSidebar, Sidebar } from './components/Sidebar'
import { Topbar } from './components/Topbar'
import { Audit } from './pages/Audit'
import { Connect } from './pages/Connect'
import { EngagementDetail } from './pages/EngagementDetail'
import { Engagements } from './pages/Engagements'
import { Team } from './pages/Team'
import Rules from './pages/Rules'
import RuleDetail from './pages/RuleDetail'
import { CodeQualityProject } from './pages/CodeQualityProject'
import { CodeQualityProjects } from './pages/CodeQualityProjects'
import { ProjectActivityPage } from './pages/ProjectActivityPage'
import { ProjectAnalysisPage } from './pages/ProjectAnalysisPage'
import { ProjectOverviewPage } from './pages/ProjectOverviewPage'
import { SecurityHotspotsPage } from './pages/SecurityHotspots'
import { ProjectIssuesPage } from './pages/ProjectIssues'
import { ProjectMeasuresPage } from './pages/ProjectMeasuresPage'
import { ProjectCodePage } from './pages/ProjectCodePage'
import { QualityGates } from './pages/QualityGates'
import { QualityProfiles } from './pages/QualityProfiles'

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
        <Route index element={<Navigate to="/engagements" replace />} />
        <Route path="engagements" element={<Engagements />} />
        <Route path="engagements/:id" element={<EngagementDetail />} />
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
        <Route path="rules" element={<Rules />} />
        <Route path="rules/:key" element={<RuleDetail />} />
        <Route path="audit" element={<Audit />} />
        <Route path="team" element={<Team />} />
        <Route path="*" element={<Navigate to="/engagements" replace />} />
      </Route>
    </Routes>
  )
}

function Shell() {
  const [menuOpen, setMenuOpen] = useState(false)
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <MobileSidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setMenuOpen(true)} />
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
