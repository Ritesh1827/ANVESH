import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { ecdatApi } from '../api'
import { authStore } from '../auth'
import { Button } from './ui'

const navigation = [
  ['Overview', '/app'],
  ['New Scan', '/app/new-scan'],
  ['Scan History', '/app/scans'],
  ['Crypto Inventory', '/app/inventory'],
  ['Risk & Priorities', '/app/risk'],
  ['Dependencies / Reachability', '/app/reachability'],
  ['Migration', '/app/migration'],
  ['Certificates', '/app/certificates'],
  ['CBOM', '/app/cbom'],
  ['Reports', '/app/reports'],
  ['Settings', '/app/settings'],
]

export default function AppShell() {
  const navigate = useNavigate()
  const email = authStore.getEmail()
  const signOut = () => {
    void ecdatApi.logout().finally(() => {
      authStore.clear()
      navigate('/login')
    })
  }

  return <div className="min-h-screen bg-canvas lg:pl-64">
    <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col bg-navy-950 lg:flex">
      <div className="border-b border-white/10 px-6 py-6"><p className="text-xl font-bold tracking-tight text-white">ANVESH</p><p className="mt-1 text-xs text-slate-300">Cryptographic readiness</p></div>
      <nav className="flex-1 space-y-1 px-3 py-5">
        {navigation.map(([label, path]) => <NavLink key={path} to={path} end={path === '/app'} className={({ isActive }) => `block rounded-lg px-3 py-2.5 text-sm font-medium transition ${isActive ? 'bg-navy-800 text-white' : 'text-slate-300 hover:bg-white/5 hover:text-white'}`}>{label}</NavLink>)}
      </nav>
      <div className="border-t border-white/10 p-4"><p className="truncate px-3 pb-2 text-xs text-slate-400">{email ?? 'Signed in'}</p><button onClick={signOut} className="w-full rounded-lg px-3 py-2 text-left text-sm font-medium text-slate-300 hover:bg-white/5 hover:text-white">Sign out</button></div>
    </aside>
    <header className="sticky top-0 z-10 border-b border-line bg-white/95 px-5 py-3 backdrop-blur lg:hidden"><div className="flex items-center justify-between"><span className="font-bold text-navy-950">ANVESH</span><Button variant="secondary" className="px-3 py-1.5" onClick={signOut}>Sign out</Button></div><nav className="mt-3 flex gap-3 overflow-x-auto pb-1">{navigation.map(([label, path]) => <NavLink key={path} to={path} end={path === '/app'} className={({ isActive }) => `whitespace-nowrap text-xs font-semibold ${isActive ? 'text-navy-800' : 'text-muted'}`}>{label}</NavLink>)}</nav></header>
    <main className="mx-auto max-w-7xl px-5 py-8 sm:px-8"><Outlet /></main>
  </div>
}
