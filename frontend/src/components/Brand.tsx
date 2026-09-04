import { Box } from 'lucide-react'

export function Brand() {
  return <>
    <span className="brand-mark" aria-hidden="true"><Box size={22} strokeWidth={2.1} /></span>
    <span>boxctl</span>
  </>
}
