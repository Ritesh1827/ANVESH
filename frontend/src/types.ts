export type Priority = 'P1' | 'P2' | 'P3' | 'P4'

export interface Risk {
  mosca_x_years: number | null
  mosca_y_years: number | null
  mosca_z_years: number | null
  urgency_flag: boolean
  hndl_flag: boolean
  priority: Priority
  reachability_weight: number | null
  classification_weight: number | null
}

export interface Evidence {
  detection_method: string
  finding_type: string
  rule_id: string | null
  location: { file_path: string; line_number: number | null; column_number: number | null; snippet: string | null }
  source_surface: string
  confidence: number
  llm_prompt_version: string | null
  llm_model: string | null
  notes: string | null
}

export interface Recommendation {
  standardized_replacement: string
  migration_path: string
  migration_path_type: string
  status: string
  alternative_replacement: string | null
  affected_protocols: string[] | null
  affected_libraries: string[] | null
  priority_order: number | null
  validation_steps: string[] | null
  advisory_note: string | null
}

export interface CryptoAsset {
  asset_id: string
  scan_id: string | null
  algorithm: string
  key_size_bits: number | null
  variant: string | null
  purpose: string
  location: string
  library: string | null
  protocol: string | null
  classification: string
  sensitivity: string
  business_criticality: string
  owner: string | null
  lifecycle_stage: string
  reachable: boolean | null
  reachability_path: string[] | null
  exposure_context: string | null
  certificate_subject: string | null
  certificate_issuer: string | null
  certificate_expiry: string | null
  certificate_serial: string | null
  source_surface: string
  evidence: Evidence
  risk: Risk | null
  recommendation: Recommendation | null
  discovered_at: string
  updated_at: string | null
  notes: string | null
}

export interface ScanMetadata {
  scan_id: string
  target: string
  status?: string
  stage?: string | null
  source_kind?: string
  completed_at: string
  asset_count: number
  certificate_asset_count: number
}

export interface Completeness {
  overall_completeness_pct: number
  surface_completeness_pct: number
  category_completeness_pct: number
  surfaces_scanned: number
  surfaces_total: number
  categories_found: number
  categories_expected: number
  total_assets_discovered: number
  total_raw_findings: number
  missing_expected_categories: string[]
  unscanned_surfaces: string[]
  surface_detail: Array<{ surface: string; status: string; files_scanned: number; assets_found: number }>
  category_detail: Array<{ category: string; found: boolean; expected: boolean; asset_count: number }>
  notes: string[]
}

export interface DashboardData {
  scan: ScanMetadata
  metrics: {
    total_assets: number
    quantum_vulnerable_count: number
    p1_count: number
    hndl_flagged_count: number
    discovery_coverage_pct: number | null
  }
  priority_counts: Record<Priority, number>
  top_critical_findings: CryptoAsset[]
  completeness: Completeness | null
}

export interface Roadmap {
  current_state: string
  risk_context: string
  recommendation_action: string
  affected_components: string[]
  migration_priority: string
  validation_steps: string[]
  composite_impact_score: number
  impact_level: string
  factor_scores: Array<{ factor: string; score: number; weighted_contribution: number }>
  narrative: string
}

export interface ReachabilitySummary {
  total_assets: number
  reachable_count: number
  unreachable_count: number
  unknown_count: number
  entry_points_found: string[]
  graph_node_count: number
  graph_edge_count: number
  reachability_rate: number
}
