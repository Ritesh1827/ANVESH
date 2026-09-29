import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { apiUrl, ecdatApi, notifyDataUpdated, useApiResource } from '../api'
import type { ScanJob, ScanListItem, SourceKind } from '../api'
import { Badge, Button, Card, ErrorState, LoadingState, PageHeader } from '../components/ui'

const POLL_INTERVAL_MS = 1500
const shortId = (value: string) => `${value.slice(0, 8)}…`

function StatusBadge({ status }: { status: string }) {
  const tone = status === 'complete' ? 'success' : status === 'failed' ? 'critical' : status === 'partial' ? 'warning' : status === 'running' ? 'info' : 'neutral'
  return <Badge tone={tone}>{status}</Badge>
}

function useScanPoll(scanId: string | null): ScanJob | null {
  const [job, setJob] = useState<ScanJob | null>(null)
  useEffect(() => {
    if (!scanId) { setJob(null); return }
    let cancelled = false
    const load = async () => {
      try {
        const current = await ecdatApi.scan(scanId)
        if (!cancelled) {
          setJob(current)
          if (current.status === 'complete' || current.status === 'failed' || current.status === 'partial') notifyDataUpdated()
          return current.status
        }
      } catch { /* keep polling on transient errors */ }
      return null
    }
    void load()
    const timer = window.setInterval(async () => {
      const status = await load()
      if (status === 'complete' || status === 'failed' || status === 'partial') window.clearInterval(timer)
    }, POLL_INTERVAL_MS)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [scanId])
  return job
}

export function NewScanPage() {
  const navigate = useNavigate()
  const [sourceKind, setSourceKind] = useState<SourceKind>('local_path')
  const [sourcePath, setSourcePath] = useState('')
  const [repoUrl, setRepoUrl] = useState('')
  const [includeCerts, setIncludeCerts] = useState(true)
  const [certPaths, setCertPaths] = useState('')
  const [binaryRefs, setBinaryRefs] = useState('')
  const [containerRefs, setContainerRefs] = useState('')
  const [infraEndpoints, setInfraEndpoints] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [scanId, setScanId] = useState<string | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [stagedId, setStagedId] = useState<string | null>(null)
  const [uploadState, setUploadState] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement | null>(null)
  const job = useScanPoll(scanId)
  const running = submitting || (job !== null && job.status !== 'complete' && job.status !== 'failed')

  const splitLines = (value: string) => value.split(/[\r\n]+/).map((line) => line.trim()).filter(Boolean)

  const stageFiles = async (files: FileList | null, target: 'source' | 'certs') => {
    if (!files || files.length === 0) return
    setUploadState('Uploading…')
    try {
      let activeId = stagedId
      if (!activeId) { const created = await ecdatApi.createUpload(); activeId = created.upload_id; setStagedId(activeId) }
      for (const file of Array.from(files)) {
        const relative = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name
        await ecdatApi.uploadFile(activeId as string, file, target === 'certs' ? `certs/${relative}` : relative)
      }
      if (target === 'source') { setSourceKind('upload_tree'); }
      setUploadState(`Staged ${files.length} file(s).`)
    } catch (reason) {
      setUploadState(null)
      setSubmitError(reason instanceof Error ? reason.message : 'Upload failed.')
    }
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setSubmitError(null)
    setSubmitting(true)
    try {
      const result = await ecdatApi.runScan({
        source_kind: sourceKind,
        source_path: sourceKind === 'local_path' ? sourcePath.trim() || undefined : undefined,
        repo_url: sourceKind === 'repo_url' ? repoUrl.trim() || undefined : undefined,
        upload_id: sourceKind === 'upload_tree' ? stagedId ?? undefined : undefined,
        include_certificates: includeCerts,
        certificate_paths: splitLines(certPaths),
        binary_refs: splitLines(binaryRefs),
        container_refs: splitLines(containerRefs),
        infrastructure_endpoints: splitLines(infraEndpoints),
      })
      setScanId(result.scan_id)
    } catch (reason) {
      setSubmitError(reason instanceof Error ? reason.message : 'Scan failed.')
    } finally {
      setSubmitting(false)
    }
  }

  return <>
    <PageHeader eyebrow="Pipeline execution" title="New scan">
      <Link to="/app/scans"><Button variant="secondary">Scan history</Button></Link>
    </PageHeader>
    <div className="grid max-w-5xl gap-6 lg:grid-cols-[1.5fr_0.7fr]">
      <Card className="p-6">
        <h2 className="font-bold">Scan real input</h2>
        <p className="mt-2 text-sm leading-6 text-muted">
          Submit your own source path, repository URL, or uploaded files. The pipeline runs as a
          background job and this page polls its status until it completes.
        </p>
        <form className="mt-6 space-y-4" onSubmit={submit}>
          <label className="block text-sm font-semibold text-navy-950">Source type
            <select value={sourceKind} onChange={(event) => setSourceKind(event.target.value as SourceKind)} className="input mt-2">
              <option value="local_path">Local server path</option>
              <option value="repo_url">Git repository URL</option>
              <option value="upload_tree">Uploaded files</option>
              <option value="demo">Sample data (demo)</option>
            </select>
          </label>
          {sourceKind === 'local_path' && <label className="block text-sm font-semibold text-navy-950">Source directory
            <input value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} className="input mt-2" placeholder="/path/to/your/code" />
          </label>}
          {sourceKind === 'repo_url' && <label className="block text-sm font-semibold text-navy-950">Repository URL
            <input value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} className="input mt-2" placeholder="https://github.com/org/repo" />
          </label>}
          {sourceKind === 'upload_tree' && <div className="rounded-lg border border-line p-4 text-sm">
            <p className="font-semibold text-navy-950">Upload a source tree</p>
            <p className="mt-1 text-muted">Files are staged on the server, then scanned from a job copy. The target is never modified.</p>
            <input ref={fileInput} type="file" multiple className="mt-3 w-full text-sm" onChange={(event) => void stageFiles(event.target.files, 'source')} />
            {uploadState && <p className="mt-2 text-success">{uploadState}</p>}
            {stagedId && <p className="mt-1 text-xs text-muted">Staging id {shortId(stagedId)}</p>}
          </div>}
          {sourceKind === 'demo' && <p className="rounded-lg bg-slate-50 p-3 text-sm text-muted">Runs the curated demo fixtures. Use this for onboarding only.</p>}
          <label className="flex items-start gap-3 rounded-lg border border-line p-4 text-sm">
            <input type="checkbox" checked={includeCerts} onChange={(event) => setIncludeCerts(event.target.checked)} className="mt-0.5" />
            <span><strong className="block text-navy-950">Include certificates</strong>
            <span className="mt-1 block text-muted">Also scan the source tree itself plus any paths below for certificate files.</span></span>
          </label>
          <label className="block text-sm font-semibold text-navy-950">Extra certificate paths <span className="font-normal text-muted">(one per line)</span>
            <textarea value={certPaths} onChange={(event) => setCertPaths(event.target.value)} className="input mt-2" rows={2} placeholder="/path/to/certs" />
          </label>
          <details className="rounded-lg border border-line p-4 text-sm" open>
            <summary className="cursor-pointer font-semibold text-navy-950">All five input surfaces</summary>
            <div className="mt-3 space-y-3">
              <label className="block font-semibold">Binary paths <span className="font-normal text-muted">(ELF/PE files or dirs, one per line)</span><textarea value={binaryRefs} onChange={(event) => setBinaryRefs(event.target.value)} className="input mt-2" rows={2} placeholder="/path/to/libcrypto.so" /></label>
              <label className="block font-semibold">Container refs <span className="font-normal text-muted">(image ref or local unpacked context dir)</span><textarea value={containerRefs} onChange={(event) => setContainerRefs(event.target.value)} className="input mt-2" rows={2} placeholder="nginx:1.25" /></label>
              <label className="block font-semibold">Infrastructure endpoints <span className="font-normal text-muted">(host or host:port)</span><textarea value={infraEndpoints} onChange={(event) => setInfraEndpoints(event.target.value)} className="input mt-2" rows={2} placeholder="example.com:443" /></label>
            </div>
          </details>
          {submitError && <p className="text-sm text-critical">{submitError}</p>}
          {job && <div className="rounded-lg bg-slate-50 p-4 text-sm">
            <div className="flex items-center gap-2"><StatusBadge status={job.status} /><span className="text-muted">{job.stage ?? ''}</span></div>
            {job.status === 'failed' && <p className="mt-2 text-critical">{job.error ?? 'Scan failed.'}</p>}
            {job.status === 'complete' && <p className="mt-2 text-success">Scan {shortId(job.scan_id)} completed with {job.asset_count} assets. The dashboard now shows this result.</p>}
          </div>}
          <div className="flex flex-wrap gap-3">
            <Button type="submit" disabled={running}>{running ? 'Scan running…' : 'Start scan'}</Button>
            {job?.status === 'complete' && <Button type="button" variant="secondary" onClick={() => navigate('/app')}>View overview</Button>}
          </div>
        </form>
      </Card>
      <Card className="p-6">
        <h2 className="font-bold">How it works</h2>
        <ul className="mt-4 space-y-3 text-sm leading-6 text-muted">
          <li>Scans run asynchronously: pending → running → complete/failed.</li>
          <li>Every scan persists in the database with its full result set.</li>
          <li>Uploads and clones live in ECDAT-owned job directories.</li>
          <li>The pipeline is advisory and does not modify targets.</li>
        </ul>
      </Card>
    </div>
  </>
}

export function ScansPage() {
  const { data, loading, error, reload } = useApiResource(ecdatApi.scans)
  useEffect(() => {
    const timer = window.setInterval(reload, 4000)
    return () => window.clearInterval(timer)
  }, [reload])
  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />
  const items: ScanListItem[] = data?.items ?? []
  return <>
    <PageHeader eyebrow={`${items.length} persisted scans`} title="Scan history">
      <Link to="/app/new-scan"><Button>New scan</Button></Link>
    </PageHeader>
    <Card className="overflow-hidden">
      {items.length ? <div className="overflow-x-auto"><table className="data-table"><thead><tr><th>Scan</th><th>Target</th><th>Status</th><th>Assets</th><th>Completed</th><th aria-label="Open" /></tr></thead><tbody>
        {items.map((item) => <tr key={item.scan_id}>
          <td className="font-semibold text-navy-950">{shortId(item.scan_id)}</td>
          <td className="max-w-xs break-all">{item.target}</td>
          <td><StatusBadge status={item.status} /></td>
          <td>{item.asset_count}</td>
          <td>{item.completed_at ? new Date(item.completed_at).toLocaleString() : '—'}</td>
          <td><Link to={`/app/scans/${item.scan_id}`} className="font-semibold text-navy-800">Open</Link></td>
        </tr>)}
      </tbody></table></div> : <p className="p-8 text-center text-sm text-muted">No scans yet. Start one from New scan.</p>}
    </Card>
  </>
}

export function ScanDetailPage({ scanId }: { scanId: string }) {
  const { data, loading, error } = useApiResource(() => ecdatApi.scan(scanId))
  const job = useScanPoll(data && data.status !== 'complete' && data.status !== 'failed' && data.status !== 'partial' ? scanId : null)
  const current: ScanJob | null | undefined = job ?? data
  const [baseline, setBaseline] = useState('')
  const [diff, setDiff] = useState<{ new_assets: string[]; removed_assets: string[]; changed_assets: string[] } | null>(null)
  const [diffError, setDiffError] = useState<string | null>(null)
  const { data: history } = useApiResource(ecdatApi.scans)
  const runDiff = async () => {
    if (!baseline) return
    setDiffError(null)
    try { setDiff(await ecdatApi.cbomDiff(scanId, baseline)) }
    catch (reason) { setDiffError(reason instanceof Error ? reason.message : 'Diff failed.') }
  }
  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />
  if (!current) return null
  return <>
    <PageHeader eyebrow={`Scan ${shortId(current.scan_id)}`} title="Scan detail">
      <Link to="/app/scans"><Button variant="secondary">Back to history</Button></Link>
    </PageHeader>
    <Card className="p-6">
      <div className="flex flex-wrap items-center gap-2"><StatusBadge status={current.status} /><span className="text-sm text-muted">{current.stage ?? ''}</span></div>
      <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">
        <div><dt className="table-label">Target</dt><dd className="mt-1 break-all text-muted">{current.target}</dd></div>
        <div><dt className="table-label">Source</dt><dd className="mt-1 text-muted">{current.source_kind}{current.source_ref ? ` · ${current.source_ref}` : ''}</dd></div>
        <div><dt className="table-label">Assets</dt><dd className="mt-1 text-muted">{current.asset_count} ({current.certificate_asset_count} certificate)</dd></div>
        <div><dt className="table-label">Priority</dt><dd className="mt-1 text-muted">P1 {current.priority_counts.P1} · P2 {current.priority_counts.P2} · P3 {current.priority_counts.P3} · P4 {current.priority_counts.P4}</dd></div>
        {current.recorded_only_surfaces.length > 0 && <div className="sm:col-span-2"><dt className="table-label">Surfaces noted</dt><dd className="mt-1 text-muted">{current.recorded_only_surfaces.join(', ')}</dd></div>}
        {current.status === 'partial' && <div className="sm:col-span-2"><dt className="table-label">Partial results</dt><dd className="mt-1 text-warning">Enrichment stopped before completion — findings below are complete through the last finished stage. {current.error}</dd></div>}
        {current.status === 'failed' && current.error && <div className="sm:col-span-2"><dt className="table-label">Error</dt><dd className="mt-1 text-critical">{current.error}</dd></div>}
      </dl>
      <div className="mt-6 flex flex-wrap gap-3">
        <a href={apiUrl(`/api/scans/${current.scan_id}/cbom/download`)}><Button variant="secondary">Download CBOM</Button></a>
        <a href={apiUrl(`/api/scans/${current.scan_id}/reports/pipeline.txt`)}><Button variant="secondary">Pipeline report</Button></a>
        <a href={apiUrl(`/api/scans/${current.scan_id}/reports/migration.txt`)}><Button variant="secondary">Migration report</Button></a>
        <a href={apiUrl(`/api/scans/${current.scan_id}/reports/certificates.txt`)}><Button variant="secondary">Certificate report</Button></a>
      </div>
    </Card>
    <Card className="mt-5 p-6">
      <h2 className="font-bold">CBOM version diff</h2>
      <p className="mt-1 text-sm text-muted">Compare this scan against an earlier baseline scan.</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <select value={baseline} onChange={(event) => setBaseline(event.target.value)} className="input max-w-xs">
          <option value="">Select baseline scan…</option>
          {(history?.items ?? []).filter((item) => item.scan_id !== scanId && item.status === 'complete').map((item) => <option key={item.scan_id} value={item.scan_id}>{shortId(item.scan_id)} · {item.target.slice(0, 40)}</option>)}
        </select>
        <Button variant="secondary" onClick={() => void runDiff()}>Compare</Button>
      </div>
      {diffError && <p className="mt-3 text-sm text-critical">{diffError}</p>}
      {diff && <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-3">
        <div><dt className="table-label">New assets</dt><dd className="mt-1 text-muted">{diff.new_assets.length}</dd></div>
        <div><dt className="table-label">Removed assets</dt><dd className="mt-1 text-muted">{diff.removed_assets.length}</dd></div>
        <div><dt className="table-label">Changed assets</dt><dd className="mt-1 text-muted">{diff.changed_assets.length}</dd></div>
      </dl>}
    </Card>
  </>
}
