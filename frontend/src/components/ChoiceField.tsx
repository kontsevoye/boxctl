import { Check, ChevronDown, Search } from 'lucide-react'
import { useEffect, useId, useMemo, useState, type KeyboardEvent } from 'react'
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
  const unique = useMemo(() => uniqueOptions(options, value), [options, value])
  if (unique.length <= 4) {
    return <fieldset className="choice-field" disabled={disabled}>
      <legend>{label}</legend>
      <div className="segmented-choice" role="radiogroup" aria-label={label}>
        {unique.map((option) => <button
          className={option.value === value ? 'selected' : ''}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          key={option.value}
          onClick={() => onChange(option.value)}
        >{option.label}</button>)}
      </div>
      {hint && <small>{hint}</small>}
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
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const selected = options.find((option) => option.value === value)
  const matches = useMemo(() => options.filter((option) => fuzzyMatch(`${option.label} ${option.value}`, query)), [options, query])

  useEffect(() => setActiveIndex(0), [query])

  const choose = (option: ChoiceOption) => {
    onChange(option.value)
    setQuery('')
    setOpen(false)
  }
  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      setOpen(false)
      setQuery('')
      return
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      setOpen(true)
      const direction = event.key === 'ArrowDown' ? 1 : -1
      setActiveIndex((current) => matches.length === 0 ? 0 : (current + direction + matches.length) % matches.length)
      return
    }
    if (event.key === 'Enter' && open && matches[activeIndex]) {
      event.preventDefault()
      choose(matches[activeIndex])
    }
  }

  return <div className="choice-field searchable-choice">
    <span>{label}</span>
    <span className="searchable-choice-control">
      <Search size={15} aria-hidden="true" />
      <input
        className="du-input du-input-sm"
        role="combobox"
        aria-label={label}
        aria-autocomplete="list"
        aria-controls={listID}
        aria-expanded={open}
        aria-activedescendant={open && matches[activeIndex] ? `${listID}-${activeIndex}` : undefined}
        disabled={disabled}
        value={open ? query : selected?.label ?? value}
        placeholder={t('search')}
        onFocus={() => { setQuery(''); setOpen(true) }}
        onBlur={() => { setQuery(''); setOpen(false) }}
        onChange={(event) => { setQuery(event.currentTarget.value); setOpen(true) }}
        onKeyDown={handleKeyDown}
      />
      <ChevronDown size={15} aria-hidden="true" />
      {open && <div className="searchable-choice-menu" id={listID} role="listbox">
        {matches.length > 0
          ? matches.map((option, index) => <button
            className={option.value === value || index === activeIndex ? 'active' : ''}
            id={`${listID}-${index}`}
            type="button"
            role="option"
            aria-selected={option.value === value}
            key={option.value}
            onMouseDown={(event) => { event.preventDefault(); choose(option) }}
            onMouseEnter={() => setActiveIndex(index)}
          ><span>{option.label}</span>{option.value === value && <Check size={15} aria-hidden="true" />}</button>)
          : <span className="searchable-choice-empty">{t('noData')}</span>}
      </div>}
    </span>
    {hint && <small>{hint}</small>}
  </div>
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
