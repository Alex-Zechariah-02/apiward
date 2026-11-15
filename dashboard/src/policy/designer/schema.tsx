import { useEffect, useId, useRef, useState } from 'react'
import { Field, describedBy } from '../../shared/ui'

// The JSON editor for an endpoint's body or header schema: the text as typed,
// parsed into the draft whenever it is a JSON object, with an issue reported
// while it is not.

export function SchemaEditor({
  label,
  value,
  editable,
  onChange,
  onIssue,
}: {
  label: string
  value: unknown
  editable: boolean
  onChange: (value: unknown) => void
  onIssue: (message: string | null) => void
}) {
  const id = useId()
  const serialised = JSON.stringify(value, null, 2)
  const [text, setText] = useState(serialised)
  const [error, setError] = useState('')
  // sent is the draft's schema as this editor last wrote it. The text is
  // replaced only when the draft's schema changes from outside (another view,
  // a template, a discard), so typing keeps its spacing and its caret.
  const sent = useRef(serialised)
  useEffect(() => {
    if (serialised === sent.current) return
    sent.current = serialised
    setText(serialised)
    setError('')
    onIssue(null)
  }, [serialised])
  // An editor that closes takes its issue with it: nothing would be left to fix it in.
  useEffect(() => () => onIssue(null), [])
  return (
    <Field id={id} label={label} hint="The gateway validates the schema on save." error={error || undefined} wide>
      <textarea
        id={id}
        className="input code-input"
        value={text}
        readOnly={!editable}
        spellCheck={false}
        aria-invalid={!!error}
        aria-describedby={describedBy(id, 'hint', error)}
        onChange={(event) => {
          const next = event.target.value
          setText(next)
          try {
            const parsed: unknown = JSON.parse(next)
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Use a JSON object.')
            setError('')
            onIssue(null)
            sent.current = JSON.stringify(parsed, null, 2)
            onChange(parsed)
          } catch (caught) {
            const message = caught instanceof Error ? caught.message : 'Enter a JSON object.'
            setError(message)
            onIssue(message)
          }
        }}
      />
    </Field>
  )
}
