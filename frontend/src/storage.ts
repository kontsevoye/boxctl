const STORAGE_PREFIX = 'boxctl'

export function readSetting(name: string): string | null {
  return localStorage.getItem(storageKey(name))
}

export function writeSetting(name: string, value: string): void {
  localStorage.setItem(storageKey(name), value)
}

function storageKey(name: string): string {
  return `${STORAGE_PREFIX}.${name}`
}
