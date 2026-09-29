import { useEffect, useState } from 'react'
import type { CryptoAsset, DashboardData, ReachabilitySummary, Roadmap, ScanMetadata } from './types'
import { authHeaders, authStore } from './auth'

const configuredApiUrl = (import.meta.env.VITE_ECDAT_API_URL ?? '/api').replace(/\/$/, '')

/** Server origin without the /api prefix (e.g. http://127.0.0.1:8000). */
export const apiOrigin = configuredApiUrl.replace(/\/api\/?$/, '')

/** Base URL for JSON API calls (paths are relative to /api). */
export const apiBase = `${apiOrigin}/api`

export interface ApiError extends Error { status?: number }

export type SourceKind = 'demo' | 'local_path' | 'repo_url' | 'upload_tree'
export type ScanStatus = 'pending' | 'running' | 'complete' | 'failed' | 'partial'

export interface RunScanInput {
  source_kind: SourceKind
  source_path?: string
  repo_url?: string
  upload_id?: string
  include_certificates?: boolean
  certificate_paths?: string[]
  certificate_upload_id?: string
  binary_refs?: string[]
  container_refs?: string[]
  infrastructure_endpoints?: string[]
}

export interface ScanListItem {
  scan_id: string
  target: string
  status: ScanStatus
  stage?: string | null
  source_kind?: string
  completed_at: string | null
  asset_count: number
  certificate_asset_count: number
}

export interface ScanJob extends ScanListItem {
  source_ref: string | null
  include_certificates: boolean
  cert_refs: string[]
  binary_refs: string[]
  container_refs: string[]
  infrastructure_endpoints: string[]
  recorded_only_surfaces: string[]
  error: string | null
  priority_counts: Record<'P1' | 'P2' | 'P3' | 'P4', number>
  hndl_flagged_count: number
  created_at: string | null
  started_at: string | null
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...init?.headers },
    ...init,
  })
  if (response.status === 401) {
    authStore.clear()
    window.dispatchEvent(new Event('ecdat-auth-expired'))
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    const error: ApiError = new Error(body.detail ?? 'The ECDAT API request failed.')
    error.status = response.status
    throw error
  }
  return response.json() as Promise<T>
}

async function uploadRequest<T>(path: string, body: FormData): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, { method: 'POST', headers: { ...authHeaders() }, body })
  if (response.status === 401) {
    authStore.clear()
    window.dispatchEvent(new Event('ecdat-auth-expired'))
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }))
    const error: ApiError = new Error(payload.detail ?? 'The ECDAT upload failed.')
    error.status = response.status
    throw error
  }
  return response.json() as Promise<T>
}

export interface OwnershipRule {
  id: number
  owner: string
  priority: number
  surface: string | null
  purpose: string | null
  algorithm_prefix: string | null
  path_contains: string | null
}

export interface CbVersionDiff {
  baseline_scan_id: string
  current_scan_id: string
  new_assets: string[]
  removed_assets: string[]
  changed_assets: string[]
  diff_timestamp: string
}

export interface PageInfo {
  total: number
  limit: number
  offset: number
  count: number
}

export interface AssetFilters {
  algorithm?: string
  purpose?: string
  classification?: string
  priority?: string
  source_surface?: string
  sort?: 'location' | 'algorithm' | 'priority' | 'purpose'
}

export interface AssetPage {
  scan: ScanMetadata
  items: CryptoAsset[]
  page: PageInfo
}

export const PAGE_SIZE = 50

function assetQuery(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '' && value !== 'all') query.set(key, String(value))
  }
  const text = query.toString()
  return text ? `?${text}` : ''
}

export const ecdatApi = {
  register: (email: string, password: string) =>
    request<{ user_id: string; email: string }>('/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) }),
  login: (email: string, password: string) =>
    request<{ token: string; user_id: string; email: string; expires_at: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  logout: () => request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),
  me: () => request<{ user_id: string; email: string }>('/auth/me'),
  dashboard: () => request<DashboardData>('/dashboard'),
  assets: (scanId?: string, page?: { limit?: number; offset?: number } & AssetFilters) =>
    request<AssetPage>(`/assets${assetQuery({ scan_id: scanId, limit: page?.limit ?? PAGE_SIZE, offset: page?.offset ?? 0, algorithm: page?.algorithm, purpose: page?.purpose, classification: page?.classification, priority: page?.priority, source_surface: page?.source_surface, sort: page?.sort })}`),
  risk: (scanId?: string, page?: { limit?: number; offset?: number; priority?: string }) =>
    request<AssetPage>(`/risk-priorities${assetQuery({ scan_id: scanId, limit: page?.limit ?? PAGE_SIZE, offset: page?.offset ?? 0, priority: page?.priority })}`),
  reachability: (scanId?: string, page?: { limit?: number; offset?: number }) =>
    request<{ scan: ScanMetadata; summary: ReachabilitySummary | null; items: CryptoAsset[]; page: PageInfo }>(`/reachability${assetQuery({ scan_id: scanId, limit: page?.limit ?? PAGE_SIZE, offset: page?.offset ?? 0 })}`),
  migration: () => request<{ scan: ScanMetadata; items: Array<{ asset: CryptoAsset; roadmap: Roadmap }> }>('/migration'),
  certificates: (scanId?: string, page?: { limit?: number; offset?: number }) =>
    request<AssetPage>(`/certificates${assetQuery({ scan_id: scanId, limit: page?.limit ?? PAGE_SIZE, offset: page?.offset ?? 0 })}`),
  cbom: () => request<CbomResponse>('/cbom'),
  reports: () => request<ReportsResponse>('/reports'),
  scans: () => request<{ items: ScanListItem[] }>('/scans'),
  scan: (scanId: string) => request<ScanJob>(`/scans/${scanId}`),
  runScan: (input: RunScanInput = { source_kind: 'demo' }) =>
    request<ScanListItem>('/scans', { method: 'POST', body: JSON.stringify(input) }),
  createUpload: () => request<{ upload_id: string }>('/uploads', { method: 'POST' }),
  uploadFile: (uploadId: string, file: File, path?: string) => {
    const form = new FormData()
    form.append('file', file, file.name)
    if (path) form.append('path', path)
    return uploadRequest<{ upload_id: string; path: string; size_bytes: number }>(`/uploads/${uploadId}/files`, form)
  },
  generateCbom: () => request<CbomResponse>('/cbom/export', { method: 'POST' }),
  ownershipRules: () => request<{ items: OwnershipRule[] }>('/ownership/rules'),
  createOwnershipRule: (rule: { owner: string; priority?: number; surface?: string; purpose?: string; algorithm_prefix?: string; path_contains?: string }) =>
    request<OwnershipRule>('/ownership/rules', { method: 'POST', body: JSON.stringify(rule) }),
  deleteOwnershipRule: (ruleId: number) =>
    request<{ ok: boolean }>(`/ownership/rules/${ruleId}`, { method: 'DELETE' }),
  cbomDiff: (scanId: string, baselineScanId: string) =>
    request<CbVersionDiff>(`/scans/${scanId}/cbom/diff?baseline_scan_id=${encodeURIComponent(baselineScanId)}`),
}

export interface CbomResponse {
  scan: ScanMetadata
  component_count: number
  format: string
  export: {
    export_id: string
    export_format: string
    metadata: { scan_timestamp: string; scanned_targets: string[]; input_surfaces: string[] }
    quality_score: {
      completeness_score: number
      evidence_coverage: number
      risk_coverage: number
      recommendation_coverage: number
      duplicate_rate: number
      overall_quality: number
    } | null
    discovery_completeness_pct: number | null
    assets: CryptoAsset[]
  }
  download_url: string
}

export interface ReportsResponse {
  scan: ScanMetadata
  items: Array<{ id: string; name: string; format: string; download_url: string; description: string }>
  history_supported: boolean
}

export function apiUrl(path: string): string {
  if (path.startsWith('http://') || path.startsWith('https://')) return path
  // Backend download URLs are server-root paths (e.g. "/api/cbom/download").
  if (path.startsWith('/api/')) return `${apiOrigin}${path}`
  // Relative paths are resolved against apiBase.
  return `${apiBase}${path.startsWith('/') ? path : `/${path}`}`
}

export function notifyDataUpdated(): void {
  window.dispatchEvent(new Event('ecdat-data-updated'))
}

export function useApiResource<T>(load: () => Promise<T>): { data: T | null; loading: boolean; error: string | null; reload: () => void } {
  const [state, setState] = useState<{ data: T | null; loading: boolean; error: string | null }>({ data: null, loading: true, error: null })
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    let cancelled = false
    setState((current) => ({ ...current, loading: true, error: null }))
    load()
      .then((data) => !cancelled && setState({ data, loading: false, error: null }))
      .catch((error: Error) => !cancelled && setState({ data: null, loading: false, error: error.message }))
    return () => { cancelled = true }
  }, [load, refreshKey])

  useEffect(() => {
    const onUpdate = () => setRefreshKey((value) => value + 1)
    window.addEventListener('ecdat-data-updated', onUpdate)
    return () => window.removeEventListener('ecdat-data-updated', onUpdate)
  }, [])

  return { ...state, reload: () => setRefreshKey((value) => value + 1) }
}

export interface PagedState {
  offset: number
  total: number | null
  loadingMore: boolean
}

export function usePagedAssets(
  load: (offset: number) => Promise<AssetPage>,
  deps: unknown[],
): { items: CryptoAsset[]; total: number | null; loading: boolean; loadingMore: boolean; error: string | null; loadMore: () => void; reload: () => void } {
  const [items, setItems] = useState<CryptoAsset[]>([])
  const [total, setTotal] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const depKey = JSON.stringify(deps)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    setItems([])
    setTotal(null)
    load(0)
      .then((page) => {
        if (cancelled) return
        setItems(page.items)
        setTotal(page.page.total)
        setLoading(false)
      })
      .catch((reason: Error) => {
        if (cancelled) return
        setError(reason.message)
        setLoading(false)
      })
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [depKey, reloadKey])

  useEffect(() => {
    const onUpdate = () => setReloadKey((value) => value + 1)
    window.addEventListener('ecdat-data-updated', onUpdate)
    return () => window.removeEventListener('ecdat-data-updated', onUpdate)
  }, [])

  const loadMore = () => {
    if (loading || loadingMore) return
    if (total !== null && items.length >= total) return
    setLoadingMore(true)
    load(items.length)
      .then((page) => {
        setItems((current) => [...current, ...page.items])
        setTotal(page.page.total)
        setLoadingMore(false)
      })
      .catch((reason: Error) => {
        setError(reason.message)
        setLoadingMore(false)
      })
  }

  return { items, total, loading, loadingMore, error, loadMore, reload: () => setReloadKey((value) => value + 1) }
}
