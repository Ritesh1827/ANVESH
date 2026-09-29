import { Navigate, Route, Routes, useParams } from 'react-router-dom'
import { useEffect, useState } from 'react'
import AppShell from './components/AppShell'
import { authStore } from './auth'
import { AboutPage, HomePage, WhyCbomPage } from './pages/PublicPages'
import PublicLayout from './pages/PublicPages'
import { ForgotPasswordPage, LoginPage, RegisterPage } from './pages/AuthPages'
import { CbomPage, CertificatesPage, InventoryPage, MigrationPage, OverviewPage, ReachabilityPage, ReportsPage, RiskPage, SettingsPage } from './pages/ProtectedPages'
import { NewScanPage, ScanDetailPage, ScansPage } from './pages/ScanPages'

function ProtectedRoute() {
  const [, setTick] = useState(0)
  useEffect(() => {
    const onExpired = () => setTick((value) => value + 1)
    window.addEventListener('ecdat-auth-expired', onExpired)
    return () => window.removeEventListener('ecdat-auth-expired', onExpired)
  }, [])
  return authStore.isSignedIn() ? <AppShell /> : <Navigate to="/login" replace />
}

function ScanDetailRoute() {
  const { scanId } = useParams()
  if (!scanId) return <Navigate to="/app/scans" replace />
  return <ScanDetailPage scanId={scanId} />
}

export default function App() { return <Routes><Route element={<PublicLayout/>}><Route path="/" element={<HomePage/>}/><Route path="/about" element={<AboutPage/>}/><Route path="/why-cbom" element={<WhyCbomPage/>}/></Route><Route path="/login" element={<LoginPage/>}/><Route path="/register" element={<RegisterPage/>}/><Route path="/forgot-password" element={<ForgotPasswordPage/>}/><Route path="/app" element={<ProtectedRoute/>}><Route index element={<OverviewPage/>}/><Route path="new-scan" element={<NewScanPage/>}/><Route path="scans" element={<ScansPage/>}/><Route path="scans/:scanId" element={<ScanDetailRoute/>}/><Route path="inventory" element={<InventoryPage/>}/><Route path="risk" element={<RiskPage/>}/><Route path="reachability" element={<ReachabilityPage/>}/><Route path="migration" element={<MigrationPage/>}/><Route path="certificates" element={<CertificatesPage/>}/><Route path="cbom" element={<CbomPage/>}/><Route path="reports" element={<ReportsPage/>}/><Route path="settings" element={<SettingsPage/>}/></Route><Route path="*" element={<Navigate to="/" replace/>}/></Routes> }
