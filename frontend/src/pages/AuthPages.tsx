import { useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ecdatApi } from '../api'
import { authStore } from '../auth'
import { Button } from '../components/ui'

function AuthFrame({ title, children }: { title: string; children: ReactNode }) { return <main className="flex min-h-screen items-center justify-center bg-canvas px-5"><section className="w-full max-w-md overflow-hidden rounded-xl border border-line bg-white"><div className="h-1 bg-saffron"/><div className="p-8"><Link to="/" className="text-sm font-bold text-navy-800">ECDAT</Link><h1 className="mt-6 text-2xl font-bold tracking-tight text-navy-950">{title}</h1>{children}</div></section></main> }
function Field({ label, type = 'text', value, onChange }: { label: string; type?: string; value: string; onChange: (value: string) => void }) { return <label className="block text-sm font-semibold text-navy-950"><span>{label}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} className="mt-2 w-full rounded-lg border border-line px-3 py-2.5 text-sm outline-none ring-navy-800 focus:ring-2" /></label> }

export function LoginPage() {
  const navigate = useNavigate(); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('')
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) { setError('Use a valid email and a password of at least 8 characters.'); return }
    setBusy(true)
    try {
      const session = await ecdatApi.login(email, password)
      authStore.setSession(session.token, session.email)
      navigate('/app')
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Sign in failed.') } finally { setBusy(false) }
  }
  return <AuthFrame title="Sign in to ECDAT"><p className="mt-2 text-sm text-muted">Accounts are stored in the ECDAT database with bcrypt-hashed passwords.</p><form className="mt-6 space-y-4" onSubmit={submit}><Field label="Email" type="email" value={email} onChange={setEmail}/><Field label="Password" type="password" value={password} onChange={setPassword}/>{error && <p className="text-sm text-critical">{error}</p>}<Button className="w-full" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button></form><div className="mt-5 flex justify-between text-sm"><Link to="/register" className="text-navy-800">Create account</Link><span className="text-muted">Sessions expire after 7 days.</span></div></AuthFrame>
}

export function RegisterPage() {
  const navigate = useNavigate(); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('')
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) { setError('Enter a valid email and password of at least 8 characters.'); return }
    setBusy(true)
    try {
      await ecdatApi.register(email, password)
      const session = await ecdatApi.login(email, password)
      authStore.setSession(session.token, session.email)
      navigate('/app')
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Registration failed.') } finally { setBusy(false) }
  }
  return <AuthFrame title="Create an ECDAT account"><p className="mt-2 text-sm text-muted">Your password is bcrypt-hashed on the server and never stored in plain text.</p><form className="mt-6 space-y-4" onSubmit={submit}><Field label="Work email" type="email" value={email} onChange={setEmail}/><Field label="Password" type="password" value={password} onChange={setPassword}/>{error && <p className="text-sm text-critical">{error}</p>}<Button className="w-full" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create account'}</Button></form><p className="mt-5 text-sm text-muted">Already have access? <Link to="/login" className="font-semibold text-navy-800">Sign in</Link></p></AuthFrame>
}

export function ForgotPasswordPage() { const [email, setEmail] = useState(''); const [sent, setSent] = useState(false); return <AuthFrame title="Reset password"><p className="mt-2 text-sm text-muted">Self-service password reset is not implemented. Contact your ECDAT administrator to reset your account.</p><form className="mt-6 space-y-4" onSubmit={(event) => { event.preventDefault(); if (/^\S+@\S+\.\S+$/.test(email)) setSent(true) }}><Field label="Email" type="email" value={email} onChange={setEmail}/>{sent && <p className="text-sm text-success">If this email has an account, an administrator can reset it. No email was sent.</p>}<Button className="w-full" type="submit">Request reset</Button></form><Link to="/login" className="mt-5 inline-block text-sm font-semibold text-navy-800">Back to sign in</Link></AuthFrame> }
