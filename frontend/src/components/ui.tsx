import type { PropsWithChildren, ReactNode } from 'react'
import type { Priority } from '../types'

export function Card({ children, className = '' }: PropsWithChildren<{ className?: string }>) {
  return <section className={`rounded-xl border border-line bg-surface ${className}`}>{children}</section>
}

export function Button({ children, className = '', variant = 'primary', ...props }: PropsWithChildren<React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' }>) {
  const styles = {
    primary: 'bg-navy-800 text-white hover:bg-navy-950',
    secondary: 'border border-line bg-white text-navy-950 hover:bg-slate-50',
    danger: 'bg-critical text-white hover:bg-red-700',
  }
  return <button className={`inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60 ${styles[variant]} ${className}`} {...props}>{children}</button>
}

export function Badge({ children, tone = 'neutral' }: PropsWithChildren<{ tone?: 'neutral' | 'success' | 'warning' | 'critical' | 'info' }>) {
  const styles = {
    neutral: 'bg-slate-100 text-slate-700',
    success: 'bg-emerald-50 text-success',
    warning: 'bg-amber-50 text-warning',
    critical: 'bg-red-50 text-critical',
    info: 'bg-blue-50 text-blue-700',
  }
  return <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${styles[tone]}`}>{children}</span>
}

export function PriorityBadge({ priority }: { priority: Priority | null | undefined }) {
  const tone = priority === 'P1' ? 'critical' : priority === 'P2' || priority === 'P3' ? 'warning' : priority === 'P4' ? 'success' : 'neutral'
  return <Badge tone={tone}>{priority ?? 'Unscored'}</Badge>
}

export function PageHeader({ eyebrow, title, children }: PropsWithChildren<{ eyebrow?: string; title: string }>) {
  return <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
    <div>
      {eyebrow && <p className="mb-1 text-xs font-bold uppercase tracking-[0.14em] text-muted">{eyebrow}</p>}
      <h1 className="text-2xl font-bold tracking-tight text-navy-950">{title}</h1>
    </div>
    {children}
  </div>
}

export function StatCard({ label, value, note, icon }: { label: string; value: ReactNode; note?: string; icon?: ReactNode }) {
  return <Card className="p-5"><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-muted">{label}</p><p className="mt-2 text-3xl font-bold tracking-tight text-navy-950">{value}</p>{note && <p className="mt-1 text-xs text-muted">{note}</p>}</div>{icon && <span className="rounded-lg bg-slate-50 p-2 text-navy-800">{icon}</span>}</div></Card>
}

export function LoadingState() { return <Card className="p-8 text-sm text-muted">Loading the current pipeline result…</Card> }
export function ErrorState({ message }: { message: string }) { return <Card className="border-red-200 p-6 text-sm text-critical">Unable to load live ECDAT data: {message}</Card> }

export function EmptyState({ children }: PropsWithChildren) { return <Card className="p-8 text-center text-sm text-muted">{children}</Card> }
