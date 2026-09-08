import { useEffect } from 'react'
import { NavLink, Route, Routes, Navigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Crosshair, Terminal, Boxes, FolderSearch, ShieldCheck, Trophy,
  GraduationCap, LayoutDashboard,
} from 'lucide-react'
import { api } from './lib/api'
import { QueryLab } from './pages/QueryLab'
import { Scenarios } from './pages/Scenarios'
import { Techniques } from './pages/Techniques'
import { Campaigns } from './pages/Campaigns'
import { Hunt } from './pages/Hunt'
import { Detections } from './pages/Detections'
import { Scoreboard } from './pages/Scoreboard'
import { Learn } from './pages/Learn'
import { Dashboard } from './pages/Dashboard'

const NAV = [
  { to: '/home', label: 'Home', icon: LayoutDashboard },
  { to: '/hunt', label: 'Hunt', icon: Terminal },
  { to: '/scenarios', label: 'Scenarios', icon: Crosshair },
  { to: '/techniques', label: 'Techniques', icon: Boxes },
  { to: '/campaigns', label: 'Campaigns', icon: FolderSearch },
  { to: '/detections', label: 'Detections', icon: ShieldCheck },
  { to: '/scoreboard', label: 'Scoreboard', icon: Trophy },
  { to: '/learn', label: 'Learn', icon: GraduationCap },
]

// Reflect the current view in the browser-tab title instead of a static
// "Hunting Range" everywhere — a small tell that this is a real product.
function useDocumentTitle() {
  const { pathname } = useLocation()
  useEffect(() => {
    const seg = pathname.split('/')[1] || 'home'
    const match = NAV.find((n) => n.to === `/${seg}`)
    const label = match?.label ?? (seg === 'hunt' ? 'Hunt' : 'Hunting Range')
    document.title = label === 'Home' ? 'Hunting Range' : `${label} · Hunting Range`
  }, [pathname])
}

export function App() {
  useDocumentTitle()
  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: api.status,
    refetchInterval: 5000,
  })
  const up = status?.engine.up ?? false

  return (
    <div className="flex h-full flex-col">
      <header className="relative flex items-center gap-6 bg-surface px-4 py-2 shadow-card">
        {/* A soft gradient hairline instead of a flat border reads as considered. */}
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-px
                        bg-gradient-to-r from-transparent via-line2 to-transparent" />
        <div className="flex items-center gap-2">
          <Crosshair size={18} className="text-accent" />
          <span className="text-h2 tracking-tight">
            <span className="bg-gradient-to-r from-txt to-txt-2 bg-clip-text text-transparent">
              Hunting Range
            </span>
          </span>
        </div>
        <nav className="flex items-center gap-1">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm ${
                  isActive
                    ? 'bg-surface3 text-txt shadow-card ring-1 ring-white/5'
                    : 'text-txt-2 hover:bg-surface2 hover:text-txt'
                }`
              }
            >
              <Icon size={15} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2 text-xs">
          <span className="relative flex h-2 w-2">
            {up && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full
                               bg-good opacity-60" />
            )}
            <span className={`relative inline-flex h-2 w-2 rounded-full ${
              up ? 'bg-good' : 'bg-mal'}`} />
          </span>
          <span className="text-txt-2">{up ? 'engine up' : 'engine down'}</span>
        </div>
      </header>

      <main className="min-h-0 flex-1">
        <Routes>
          <Route path="/" element={<Navigate to="/home" replace />} />
          <Route path="/home" element={<Dashboard />} />
          <Route path="/hunt" element={<QueryLab />} />
          <Route path="/scenarios" element={<Scenarios />} />
          <Route path="/techniques" element={<Techniques />} />
          <Route path="/campaigns" element={<Campaigns />} />
          <Route path="/hunt/:id" element={<Hunt />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/scoreboard" element={<Scoreboard />} />
          <Route path="/learn" element={<Learn />} />
        </Routes>
      </main>
    </div>
  )
}
