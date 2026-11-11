// The suite's Playwright global setup: builds the programs and the web root
// once, before any worker starts, for every deployment of the run to share.
import { prepare } from '../../../fetch/e2e/backend'
import { webRoot } from './env'

export default function setup(): void {
  prepare(webRoot)
}
