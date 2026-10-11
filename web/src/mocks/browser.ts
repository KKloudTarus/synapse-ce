import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'

const exercise = import.meta.env.VITE_PLAYGROUND === '1'
  ? (await import('../playground/scenario/handlers')).scenarioHandlers
  : []

const workflows = import.meta.env.VITE_PLAYGROUND === '1'
  ? (await import('../playground/workflows/handlers')).workflowHandlers
  : []

const advanced = import.meta.env.VITE_PLAYGROUND === '1'
  ? (await import('../playground/advanced/handlers')).advancedHandlers
  : []

const setup = import.meta.env.VITE_PLAYGROUND === '1'
  ? (await import('../playground/setup/handlers')).setupHandlers
  : []

export const worker = setupWorker(...setup, ...advanced, ...workflows, ...exercise, ...handlers)
