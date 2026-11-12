import { useEffect, useMemo, useRef, useState } from 'react'
import {
  ReactFlow,
  ReactFlowProvider,
  Panel,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  applyNodeChanges,
  type NodeChange,
  type Viewport,
} from '@xyflow/react'
import { CornersIn, CornersOut } from '@phosphor-icons/react'
import '@xyflow/react/dist/base.css'
import { deleteReason, splitKey, type BoxKind } from './model'
import { type CardNode, edgeTypes, nodeTypes } from './card'
import { buildGraph, type CanvasProps } from './graph'
import { useZone } from '../../shared/zone'
import { fitTo, focusOn, useCanvasHeight } from './camera'

// The Designer's canvas: the draft's boxes and links, moved and fitted to the window.

// Card widths and the space between columns are sized so the first fit
// beside the open sidebar stays readable at 1280 px; 24 px still leaves
// room for a connection's bend and arrowhead.
const kinds: BoxKind[] = ['role', 'operation', 'api', 'upstream']
const widths: Record<BoxKind, number> = { role: 200, operation: 360, api: 180, upstream: 200 }
const columnGap = 24
const columnX = Object.fromEntries(
  kinds.map((kind, index) => [kind, kinds.slice(0, index).reduce((x, before) => x + widths[before] + columnGap, 0)]),
) as Record<BoxKind, number>
const gap = 20

function CanvasGraph(props: CanvasProps) {
  const flow = useReactFlow()
  const [message, setMessage] = useState('')
  const measured = useNodesInitialized()
  const placed = useRef(false)
  // refit is set by Expand All and Collapse All: once the cards have their
  // new sizes, every card is fitted again. Opening or closing one group
  // leaves the view where it is.
  const refit = useRef(false)
  const settle = useRef<ReturnType<typeof setTimeout>>(undefined)
  useEffect(() => () => clearTimeout(settle.current), [])
  // Which groups are open. Roles start open; endpoint lists start closed and
  // open on demand, or by themselves for the selected or traced endpoint.
  const [open, setOpen] = useState<Set<string>>(() => new Set(['roles']))
  const focusedOperation = props.selection?.startsWith('operation:') ? splitKey(props.selection)[1] : props.trace?.operation
  const focusedApi = props.policy.operations.find((operation) => operation.id === focusedOperation)?.api
  useEffect(() => {
    if (focusedApi === undefined) return
    const group = props.policy.apis.some((api) => api.id === focusedApi) ? `api:${focusedApi}` : 'api:'
    if (!open.has(group)) setOpen((previous) => new Set(previous).add(group))
  }, [focusedApi, focusedOperation])

  const zone = useZone()
  const graph = useMemo(() => buildGraph(props, zone), [props.policy, props.selection, props.issues, props.overlays, props.provisional, props.refused, props.trace, zone])

  // Cards stand in four columns from one top line, so a group that opens or
  // closes moves only the cards below it in its own column.
  function laidOut(heights: Record<string, number>): CardNode[] {
    const height = (id: string) => heights[id] ?? 56
    const columns = kinds.map((kind) => graph.cards.filter((card) => card.kind === kind))
    return columns.flatMap((list, index) => {
      let y = 0
      return list.map((card) => {
        const node: CardNode = {
          id: card.id,
          type: 'card',
          position: { x: columnX[kinds[index]], y },
          style: { width: widths[kinds[index]] },
          className: `designer-node-${kinds[index]}`,
          draggable: false,
          selectable: false,
          focusable: false,
          ariaRole: 'group',
          data: {
            ...card.data,
            open: !card.data.collapsible || open.has(card.id),
            actions: props.editable ? props.actions(card.kind, card.api) : [],
            selection: props.selection,
            onSelect: props.onSelect,
            onToggle: () => {
              setOpen((previous) => {
                const next = new Set(previous)
                if (next.has(card.id)) next.delete(card.id)
                else next.add(card.id)
                return next
              })
            },
          },
        }
        y += height(card.id) + gap
        return node
      })
    })
  }
  const heightsOf = (list: CardNode[]) =>
    Object.fromEntries(list.filter((node) => node.measured?.height).map((node) => [node.id, node.measured!.height!]))
  const keepMeasured = (laid: CardNode[], from: CardNode[]) =>
    laid.map((node) => ({ ...node, measured: from.find((old) => old.id === node.id)?.measured }))
  const [nodes, setNodes] = useNodesState<CardNode>(laidOut({}))
  useEffect(() => {
    setNodes((previous) => keepMeasured(laidOut(heightsOf(previous)), previous))
  }, [graph, open, props.editable])
  function onNodesChange(changes: NodeChange<CardNode>[]) {
    setNodes((previous) => {
      const updated = applyNodeChanges(changes, previous)
      if (!changes.some((change) => change.type === 'dimensions')) return updated
      // The view moves once the cards stop changing size, so it lands where
      // they end, not on a frame of their opening.
      if (refit.current) {
        clearTimeout(settle.current)
        settle.current = setTimeout(() => {
          if (!refit.current) return
          refit.current = false
          fitTo(flow, area.current)
        }, 80)
      }
      return keepMeasured(laidOut(heightsOf(updated)), updated)
    })
  }
  useEffect(() => {
    if (!measured || placed.current) return
    placed.current = true
    fitTo(flow, area.current)
  }, [measured])
  useEffect(() => {
    if (placed.current) fitTo(flow, area.current)
  }, [props.expanded])

  const area = useRef<HTMLDivElement>(null)
  const before = useRef<Viewport | null>(null)
  // pendingFocus is the timer that will bring the selection into view.
  const pendingFocus = useRef<ReturnType<typeof setTimeout>>(undefined)
  const height = useCanvasHeight(area, props.expanded)
  useEffect(() => {
    if (placed.current) fitTo(flow, area.current)
  }, [height])
  useEffect(() => {
    if (!props.panelOpen) {
      if (before.current) void flow.setViewport(before.current)
      before.current = null
      return
    }
    const key = props.selection ?? (props.trace ? `operation:${props.trace.operation}` : null)
    if (!key) return
    // A selection can open its group first, so the row is measured once the
    // cards have taken their new sizes.
    const timer = setTimeout(() => {
      pendingFocus.current = undefined
      const canvas = area.current
      const row = canvas?.querySelector(`[data-box="${CSS.escape(key)}"]`) ?? canvas?.querySelector(`[data-box^="${CSS.escape(key.split(':')[0])}:"]`)
      const panel = canvas?.closest('.designer-workspace')?.querySelector('.designer-side-panel')
      if (!canvas || !row || !panel) return
      // An endpoint is brought into view at a readable size beside the form.
      if (key.startsWith('operation:') && row.getAttribute('data-box') === key) {
        before.current ??= flow.getViewport()
        const box = row.getBoundingClientRect()
        const start = flow.screenToFlowPosition({ x: box.left, y: box.top })
        const end = flow.screenToFlowPosition({ x: box.right, y: box.bottom })
        focusOn(flow, area.current, { x: start.x, y: start.y, width: end.x - start.x, height: end.y - start.y })
        return
      }
      const rowBox = row.getBoundingClientRect()
      const panelBox = panel.getBoundingClientRect()
      const canvasBox = canvas.getBoundingClientRect()
      // A narrow screen stacks the form under the canvas: nothing is covered.
      if (panelBox.top >= canvasBox.bottom - 1) return
      const room = 24
      const shift = panelBox.left - room - rowBox.right
      if (shift >= 0) return
      const viewport = flow.getViewport()
      before.current ??= viewport
      // Move left by what is covered, but never push the row off the left edge.
      const limit = canvasBox.left + room - rowBox.left
      void flow.setViewport({ ...viewport, x: viewport.x + Math.max(shift, Math.min(0, limit)) })
    }, 120)
    pendingFocus.current = timer
    return () => clearTimeout(timer)
  }, [props.panelOpen, props.selection, props.trace?.operation])

  // cancelMoves drops a selection still waiting to be brought into view and a
  // group still settling, so the fit the person asked for wins over both.
  function cancelMoves() {
    clearTimeout(pendingFocus.current)
    pendingFocus.current = undefined
    clearTimeout(settle.current)
    refit.current = false
  }

  function setAll(state: 'open' | 'closed') {
    cancelMoves()
    refit.current = true
    setOpen(state === 'open' ? new Set(graph.cards.filter((card) => card.data.collapsible).map((card) => card.id)) : new Set())
  }

  return (
    <>
      <div
        ref={area}
        className="designer-canvas"
        style={height ? { height } : undefined}
        role="region"
        aria-label="Policy canvas"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.target === event.currentTarget && ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) {
            event.preventDefault()
            const viewport = flow.getViewport()
            const x = event.key === 'ArrowLeft' ? 32 : event.key === 'ArrowRight' ? -32 : 0
            const y = event.key === 'ArrowUp' ? 32 : event.key === 'ArrowDown' ? -32 : 0
            void flow.setViewport({ ...viewport, x: viewport.x + x, y: viewport.y + y })
            return
          }
          if (event.key === 'Escape' && props.expanded) {
            props.onExpand()
            return
          }
          if (event.key !== 'Delete' || !props.editable || !props.selection) return
          if ((event.target as HTMLElement).closest('input,textarea,select')) return
          event.preventDefault()
          const reason = deleteReason(props.policy, props.selection)
          if (reason) setMessage(reason)
          else props.onDelete(props.selection)
        }}
      >
        <ReactFlow<CardNode>
          nodes={nodes}
          edges={graph.edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          colorMode="light"
          // The library's MIT licence allows its attribution to be hidden.
          proOptions={{ hideAttribution: true }}
          // Low enough that every group open still fits a short canvas.
          minZoom={0.1}
          // The wheel moves around the canvas like a page; pinch or Ctrl and
          // the wheel zoom.
          panOnScroll
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          deleteKeyCode={null}
          onNodesChange={onNodesChange}
        >
          <Panel position="top-right" className="designer-viewport-controls">
            {props.tools ? <div className="designer-canvas-tools">{props.tools}</div> : null}
            <button className="btn btn-small" type="button" onClick={() => setAll('open')}>
              Expand All
            </button>
            <button className="btn btn-small" type="button" onClick={() => setAll('closed')}>
              Collapse All
            </button>
            <button
              className="btn btn-small"
              type="button"
              onClick={() => {
                cancelMoves()
                fitTo(flow, area.current)
              }}
            >
              Fit
            </button>
            <button className="btn btn-small" type="button" aria-pressed={props.expanded} onClick={props.onExpand}>
              {props.expanded ? <CornersIn size={16} aria-hidden="true" /> : <CornersOut size={16} aria-hidden="true" />}
              {props.expanded ? 'Exit Full Screen' : 'Full Screen'}
            </button>
          </Panel>
        </ReactFlow>
      </div>
      {message ? (
        <p role="status" className="hint">
          {message}
        </p>
      ) : null}
    </>
  )
}

export function DesignerCanvas(props: CanvasProps) {
  return (
    <ReactFlowProvider>
      <CanvasGraph {...props} />
    </ReactFlowProvider>
  )
}
