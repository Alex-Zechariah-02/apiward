import { useId, useRef, useState, type FormEvent } from 'react'
import { newKey } from '../shared/http'
import type { Candidate, Outcome, Revision } from '../shared/api'
import { useMutation } from '../shared/hooks'
import { readPolicy, sizeProblem, usePolicyLimit } from '../shared/limits'
import { describedBy, Field } from '../shared/ui'
import { Confirm } from '../shared/dialogs'
import { MutationResult, Receipt } from '../shared/replies'
import type { ViewProps } from '../app/views'

// The Changes page's form that saves a draft change: a link to the Policy
// page, or the whole document pasted, loaded from a file or started from the
// active version, then sent to the gateway to check and save.

export function StageForm(props: {
  admin: ViewProps['admin']
  ifMatch?: string
  draft?: string
  confirmed?: Revision
  changed: () => void
  review: (id: number) => void
}) {
  const id = useId()
  const [text, setText] = useState(props.draft ?? '')
  const [replacing, setReplacing] = useState(false)
  // advanced shows the document editor; a draft handed over from another page opens it.
  const [advanced, setAdvanced] = useState(props.draft !== undefined)
  const editor = useRef<HTMLTextAreaElement>(null)
  const mutation = useMutation<{ receipt: Outcome; candidate: Candidate }>(props.admin, props.changed)
  // limit is the gateway's own policy size limit; until it is read, only the gateway checks the size.
  const limit = usePolicyLimit(props.admin)
  const [fileProblem, setFileProblem] = useState('')
  const bytes = new TextEncoder().encode(text).length
  let localError: string | undefined
  if (text.trim() !== '') {
    try {
      JSON.parse(text)
    } catch {
      localError = 'This is not valid JSON.'
    }
  }
  localError = sizeProblem('document', bytes, limit) ?? localError

  async function load(file: File | undefined) {
    if (!file) return
    const read = await readPolicy(file, limit)
    setFileProblem('problem' in read ? read.problem : '')
    if ('text' in read) setText(read.text)
  }

  // startFromConfirmed puts the confirmed document in the editor, to be
  // changed and staged as a whole: a change is always a complete policy.
  function startFromConfirmed() {
    setReplacing(false)
    if (!props.confirmed?.document) return
    setText(JSON.stringify(props.confirmed.document, null, 2))
    setAdvanced(true)
    requestAnimationFrame(() => editor.current?.focus())
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (localError || text.trim() === '') return
    // The document is sent as written, so the gateway's strict decoder sees
    // exactly what the administrator reviewed (repeated members included).
    await mutation.run({ method: 'POST', path: '/admin/candidates', rawBody: `{"policy":${text}}`, ifMatch: props.ifMatch, key: newKey() })
  }

  return (
    <section className="section card card-pad" aria-labelledby="stage-title">
      <h2 id="stage-title">Save a Draft Change</h2>
      <p className="hint form-intro">
        Draft the change on the Policy page, where every view checks it as you edit. To change the document itself, start from the active version.
      </p>
      <div className="actions">
        <a className="btn btn-primary" href="#/policy">
          Open the Policy Page
        </a>
        {props.confirmed?.document ? (
          <button type="button" className="btn" onClick={() => (text.trim() === '' ? startFromConfirmed() : setReplacing(true))}>
            Start from Version {props.confirmed.id}
          </button>
        ) : null}
      </div>
      <details className="advanced" open={advanced} onToggle={(event) => setAdvanced(event.currentTarget.open)}>
        <summary>Advanced: Paste or Load a Policy Document</summary>
        <form className="advanced-body" onSubmit={submit}>
          <Field id={`${id}-file`} label="Load a Policy Document from a File (Optional)" error={fileProblem || undefined}>
            <input
              id={`${id}-file`}
              className="file"
              type="file"
              accept="application/json,.json"
              aria-invalid={fileProblem ? true : undefined}
              aria-describedby={describedBy(`${id}-file`, undefined, fileProblem)}
              onChange={(e) => void load(e.target.files?.[0])}
            />
          </Field>
          <Field
            id={`${id}-text`}
            label="Complete Policy Document (JSON)"
            hint={`Checked by the gateway with the same compiler that builds the enforced policy. ${bytes.toLocaleString()}${limit === undefined ? '' : ` of ${limit.toLocaleString()}`} bytes.`}
            error={localError}
          >
            <textarea
              ref={editor}
              id={`${id}-text`}
              className="input code-input"
              rows={8}
              spellCheck={false}
              autoComplete="off"
              value={text}
              aria-invalid={localError ? true : undefined}
              aria-describedby={describedBy(`${id}-text`, 'hint', localError)}
              onChange={(e) => setText(e.target.value)}
            />
          </Field>
          <div className="actions">
            <button type="submit" className="btn btn-primary" disabled={mutation.pending || props.ifMatch === undefined || text.trim() === ''}>
              {mutation.pending ? 'Saving…' : 'Save Draft and Check'}
            </button>
          </div>
          </form>
      </details>
      <Confirm
        open={replacing}
        title="Replace the document being edited?"
        confirmLabel="Replace It"
        onCancel={() => setReplacing(false)}
        onConfirm={startFromConfirmed}
      >
        <p>The text in the editor is replaced by version {props.confirmed?.id}, the active version. Nothing is sent to the gateway.</p>
      </Confirm>
      <MutationResult<{ receipt: Outcome; candidate: Candidate }>
        mutation={mutation}
        onRefresh={props.changed}
        success={(body) => (
          <>
            <p className="notice-title">The gateway checked it: saved as draft change {body.candidate.id}. Nothing is active yet.</p>
            <div className="actions">
              <button type="button" className="btn" onClick={() => props.review(body.candidate.id)}>
                Review Change {body.candidate.id}
              </button>
            </div>
            <Receipt outcome={body.receipt} />
          </>
        )}
      />
    </section>
  )
}
