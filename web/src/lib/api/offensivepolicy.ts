import { ApiError, req } from './client'

/**
 * Offensive policy register (read-only), showing exactly what the running binary enforces for offensive
 * techniques: for each classified technique its disruption, reversibility, risk class, approval mode,
 * blast radius, and whether the binary treats it as production-safe or prohibited. The legal-review block
 * records whether counsel signed off. This is the loaded register, identical for every operator; there is
 * no write path here. Route registers only when the register is wired, so a 404 means "not enabled".
 *
 * SOURCE OF TRUTH: `internal/adapter/httpapi/offensive_policy_handler.go` (`offensivePolicyDTO`).
 */

export interface OffensiveTechnique {
  technique: string
  taxonomyRef: string
  disruption: string
  reversibility: string
  riskClass: string
  approval: string
  blastRadius: string
  productionSafe: boolean
  prohibited: boolean
}

export interface OffensiveLegalReview {
  reviewed: boolean
  date: string
  owner: string
  counselReviewed: boolean
  counselDate: string
}

export interface OffensivePolicy {
  legalReview: OffensiveLegalReview
  techniques: OffensiveTechnique[]
  prohibited: number
  productionSafe: number
}

function mapTechnique(t: any): OffensiveTechnique {
  return {
    technique: t?.technique ?? '',
    taxonomyRef: t?.taxonomy_ref ?? '',
    disruption: t?.disruption ?? '',
    reversibility: t?.reversibility ?? '',
    riskClass: t?.risk_class ?? '',
    approval: t?.approval ?? '',
    blastRadius: t?.blast_radius ?? '',
    productionSafe: t?.production_safe === true,
    prohibited: t?.prohibited === true,
  }
}

export const offensivePolicyApi = {
  /** null when the deployment does not expose the offensive policy register (route 404). */
  offensivePolicy: async (): Promise<OffensivePolicy | null> => {
    try {
      const r = await req('/redteam/policy')
      const lr = r?.legal_review ?? {}
      return {
        legalReview: {
          reviewed: lr.reviewed === true,
          date: lr.date ?? '',
          owner: lr.owner ?? '',
          counselReviewed: lr.counsel_reviewed === true,
          counselDate: lr.counsel_date ?? '',
        },
        techniques: Array.isArray(r?.techniques) ? r.techniques.map(mapTechnique) : [],
        prohibited: r?.prohibited ?? 0,
        productionSafe: r?.production_safe ?? 0,
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  },
}
