// A lightweight toast system, introduced in the Tier-2 polish pass. Mutations
// across the app previously either failed silently (a bare navigation on
// success) or showed small red text next to a button. A consistent corner
// notification for build-started / saved / completed / error is a strong
// "feels like a product" signal and keeps feedback out of the layout.

import {
  createContext, useCallback, useContext, useRef, useState, type ReactNode,
} from 'react'
import { CheckCircle2, AlertCircle, Info, X, Loader2 } from 'lucide-react'

type ToastKind = 'success' | 'error' | 'info' | 'pending'

interface Toast {
  id: number
  kind: ToastKind
  title: string
  description?: string
}

interface ToastApi {
  toast: (t: Omit<Toast, 'id'>) => number
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastApi | null>(null)

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within <ToastProvider>')
  return ctx
}

const KIND_STYLE: Record<ToastKind, { icon: ReactNode; ring: string }> = {
  success: { icon: <CheckCircle2 size={16} className="text-good" />, ring: 'ring-good/20' },
  error: { icon: <AlertCircle size={16} className="text-mal" />, ring: 'ring-mal/20' },
  info: { icon: <Info size={16} className="text-accent-light" />, ring: 'ring-accent/20' },
  pending: { icon: <Loader2 size={16} className="animate-spin text-txt-2" />, ring: 'ring-white/5' },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const idRef = useRef(0)

  const dismiss = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id))
  }, [])

  const toast = useCallback((t: Omit<Toast, 'id'>) => {
    const id = ++idRef.current
    setToasts((ts) => [...ts, { ...t, id }])
    // Pending toasts stay until dismissed/updated by the caller; the rest auto-clear.
    if (t.kind !== 'pending') {
      setTimeout(() => dismiss(id), t.kind === 'error' ? 6000 : 3500)
    }
    return id
  }, [dismiss])

  return (
    <ToastContext.Provider value={{ toast, dismiss }}>
      {children}
      {/* Stack, bottom-right, above everything. */}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start gap-3 rounded-lg border border-line2
                        bg-surface3 px-3.5 py-3 shadow-overlay ring-1 ${KIND_STYLE[t.kind].ring}
                        animate-[toastIn_180ms_ease-out]`}
          >
            <span className="mt-0.5 shrink-0">{KIND_STYLE[t.kind].icon}</span>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-txt">{t.title}</div>
              {t.description && (
                <div className="mt-0.5 text-xs text-txt-2">{t.description}</div>
              )}
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className="shrink-0 text-txt-3 hover:text-txt"
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
