import { Check, ChevronDown, Search } from 'lucide-react'
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useI18n } from '../i18n'

export interface ChoiceOption {
  value: string
  label: string
}

export function ChoiceField({ label, value, options, onChange, hint, disabled = false }: {
  label: string
  value: string
  options: ChoiceOption[]
  onChange: (value: string) => void
  hint?: string
  disabled?: boolean
}) {
  const fieldID = useId()
  const groupRef = useRef<HTMLDivElement>(null)
  const unique = useMemo(() => uniqueOptions(options, value), [options, value])
  const selectedIndex = Math.max(0, unique.findIndex((option) => option.value === value))
  if (unique.length <= 4) {
    return <fieldset className="choice-field" disabled={disabled}>
      <legend id={fieldID}>{label}</legend>
      <div className="segmented-choice" ref={groupRef} role="radiogroup" aria-labelledby={fieldID} aria-describedby={hint ? `${fieldID}-hint` : undefined}>
        {unique.map((option, index) => <button
          className={option.value === value ? 'selected' : ''}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          tabIndex={!disabled && index === selectedIndex ? 0 : -1}
          key={option.value}
          onClick={() => onChange(option.value)}
          onKeyDown={(event) => {
            if (event.altKey || event.ctrlKey || event.metaKey) return
            const nextIndex = choiceIndexForKey(event.key, index, unique.length)
            if (nextIndex === null) return
            const next = unique[nextIndex]
            if (!next || disabled) return
            event.preventDefault()
            groupRef.current?.querySelectorAll<HTMLButtonElement>('button')[nextIndex]?.focus()
            onChange(next.value)
          }}
        >{option.label}</button>)}
      </div>
      {hint && <small id={`${fieldID}-hint`}>{hint}</small>}
    </fieldset>
  }
  return <SearchableChoice label={label} value={value} options={unique} onChange={onChange} hint={hint} disabled={disabled} />
}

function SearchableChoice({ label, value, options, onChange, hint, disabled }: {
  label: string
  value: string
  options: ChoiceOption[]
  onChange: (value: string) => void
  hint?: string
  disabled: boolean
}) {
  const { t } = useI18n()
  const listID = useId()
  const menuRef = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const selected = options.find((option) => option.value === value)
  const matches = useMemo(() => options.filter((option) => fuzzyMatch(`${option.label} ${option.value}`, query)), [options, query])

  useEffect(() => {
    if (open) menuRef.current?.querySelector<HTMLElement>(`[data-choice-index="${activeIndex}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [open, activeIndex, matches])

  const openMenu = () => {
    if (disabled || open) return
    setQuery('')
    setActiveIndex(Math.max(0, options.findIndex((option) => option.value === value)))
    setOpen(true)
  }

  const choose = (option: ChoiceOption) => {
    onChange(option.value)
    setQuery('')
    setOpen(false)
  }
  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return
    if (event.key === 'Escape') {
      if (open) event.stopPropagation()
      setOpen(false)
      setQuery('')
      return
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      if (!open) openMenu()
      else setActiveIndex((current) => choiceIndexForKey(event.key, current, matches.length) ?? 0)
      return
    }
    if (open && (event.key === 'Home' || event.key === 'End')) {
      event.preventDefault()
      setActiveIndex(choiceIndexForKey(event.key, activeIndex, matches.length) ?? 0)
      return
    }
    if (event.key === 'Enter' && open) {
      event.preventDefault()
      const option = matches[activeIndex]
      if (option) choose(option)
    }
  }

  return <div className="choice-field searchable-choice">
    <label htmlFor={`${listID}-input`}>{label}</label>
    <span className="searchable-choice-control">
      <Search size={15} aria-hidden="true" />
      <input
        className="du-input du-input-sm"
        id={`${listID}-input`}
        role="combobox"
        aria-autocomplete="list"
        aria-controls={listID}
        aria-expanded={open && !disabled}
        aria-describedby={hint ? `${listID}-hint` : undefined}
        aria-activedescendant={open && !disabled && matches[activeIndex] ? `${listID}-${activeIndex}` : undefined}
        autoComplete="off"
        disabled={disabled}
        value={open ? query : selected?.label ?? value}
        placeholder={t('search')}
        onFocus={openMenu}
        onClick={openMenu}
        onBlur={() => { setQuery(''); setOpen(false) }}
        onChange={(event) => { setQuery(event.currentTarget.value); setActiveIndex(0); setOpen(true) }}
        onKeyDown={handleKeyDown}
      />
      <ChevronDown size={15} aria-hidden="true" />
      {open && !disabled && <div className="searchable-choice-menu" id={listID} ref={menuRef} role="listbox" aria-label={label}>
        {matches.length > 0
          ? matches.map((option, index) => <button
            className={`${index === activeIndex ? 'active' : ''} ${option.value === value ? 'selected' : ''}`.trim()}
            id={`${listID}-${index}`}
            data-choice-index={index}
            type="button"
            role="option"
            tabIndex={-1}
            aria-selected={option.value === value}
            key={option.value}
            onMouseDown={(event) => event.preventDefault()}
            onClick={() => choose(option)}
            onMouseEnter={() => setActiveIndex(index)}
          ><span>{option.label}</span>{option.value === value && <Check size={15} aria-hidden="true" />}</button>)
          : <span className="searchable-choice-empty">{t('noData')}</span>}
      </div>}
    </span>
    {hint && <small id={`${listID}-hint`}>{hint}</small>}
  </div>
}

export function choiceIndexForKey(key: string, current: number, count: number): number | null {
  if (count === 0) return null
  if (key === 'Home') return 0
  if (key === 'End') return count - 1
  if (key === 'ArrowRight' || key === 'ArrowDown') return (current + 1) % count
  if (key === 'ArrowLeft' || key === 'ArrowUp') return (current - 1 + count) % count
  return null
}

export function fuzzyMatch(value: string, query: string): boolean {
  const haystack = value.toLocaleLowerCase()
  const needle = query.trim().toLocaleLowerCase()
  if (!needle || haystack.includes(needle)) return true
  let cursor = 0
  for (const character of needle) {
    cursor = haystack.indexOf(character, cursor)
    if (cursor < 0) return false
    cursor++
  }
  return true
}

function uniqueOptions(options: ChoiceOption[], current: string): ChoiceOption[] {
  const values = new Set<string>()
  const result = options.filter((option) => {
    if (option.value === '' || values.has(option.value)) return false
    values.add(option.value)
    return true
  })
  if (current && !values.has(current)) result.unshift({ value: current, label: current })
  return result
}
