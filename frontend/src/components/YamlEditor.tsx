import { yaml } from '@codemirror/lang-yaml'
import { oneDark } from '@codemirror/theme-one-dark'
import { Compartment, EditorState } from '@codemirror/state'
import { EditorView, basicSetup } from 'codemirror'
import { useEffect, useRef } from 'react'
import './YamlEditor.css'

interface YamlEditorProps {
  value: string
  onChange: (value: string) => void
  ariaLabel: string
}

export function YamlEditor({ value, onChange, ariaLabel }: YamlEditorProps) {
  const host = useRef<HTMLDivElement>(null)
  const view = useRef<EditorView | undefined>(undefined)
  const onChangeRef = useRef(onChange)
  const attributes = useRef(new Compartment())
  const editorTheme = useRef(new Compartment())
  const syncing = useRef(false)

  onChangeRef.current = onChange

  useEffect(() => {
    const editorHost = host.current
    if (!editorHost) return
    const styleNonce = document.querySelector<HTMLMetaElement>('meta[name="boxctl-style-nonce"]')?.content

    const editor = new EditorView({
      parent: editorHost,
      state: EditorState.create({
        doc: value,
        extensions: [
          basicSetup,
          yaml(),
          ...(styleNonce ? [EditorView.cspNonce.of(styleNonce)] : []),
          editorTheme.current.of(activeEditorTheme()),
          EditorView.lineWrapping,
          attributes.current.of(EditorView.contentAttributes.of({
            'aria-label': ariaLabel,
            'aria-multiline': 'true',
            role: 'textbox',
          })),
          EditorView.updateListener.of((update) => {
            if (update.docChanged && !syncing.current) onChangeRef.current(update.state.doc.toString())
          }),
        ],
      }),
    })
    view.current = editor
    const resizeObserver = new ResizeObserver(() => editor.requestMeasure())
    resizeObserver.observe(editorHost)

    return () => {
      resizeObserver.disconnect()
      editor.destroy()
      view.current = undefined
    }
    // The document is synchronized separately so the editor and its selection survive parent renders.
  }, [])

  useEffect(() => {
    const editor = view.current
    if (!editor || editor.state.doc.toString() === value) return
    syncing.current = true
    editor.dispatch({ changes: { from: 0, to: editor.state.doc.length, insert: value } })
    syncing.current = false
  }, [value])

  useEffect(() => {
    view.current?.dispatch({
      effects: attributes.current.reconfigure(EditorView.contentAttributes.of({
        'aria-label': ariaLabel,
        'aria-multiline': 'true',
        role: 'textbox',
      })),
    })
  }, [ariaLabel])

  useEffect(() => {
    const applyEditorTheme = () => view.current?.dispatch({
      effects: editorTheme.current.reconfigure(activeEditorTheme()),
    })
    const rootObserver = new MutationObserver(applyEditorTheme)
    rootObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    const colorScheme = window.matchMedia('(prefers-color-scheme: light)')
    colorScheme.addEventListener('change', applyEditorTheme)
    return () => {
      rootObserver.disconnect()
      colorScheme.removeEventListener('change', applyEditorTheme)
    }
  }, [])

  return <div ref={host} className="yaml-editor" />
}

function activeEditorTheme() {
  return getComputedStyle(document.documentElement).colorScheme.includes('light') ? [] : oneDark
}
