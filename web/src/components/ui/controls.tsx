import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '../../lib/utils'

/* -------------------------------------------------------------------------- */
/* Buttons                                                                    */
/* -------------------------------------------------------------------------- */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
type ButtonSize = 'sm' | 'md'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  icon?: ReactNode
  iconRight?: ReactNode
}

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-blue-600 text-white hover:bg-blue-700 focus-visible:ring-blue-500/40 shadow-xs border border-transparent',
  secondary:
    'bg-white text-slate-700 border border-slate-200 hover:bg-slate-50 focus-visible:ring-blue-500/30',
  ghost: 'bg-transparent text-slate-600 border border-transparent hover:bg-slate-100',
  danger:
    'bg-red-600 text-white hover:bg-red-700 focus-visible:ring-red-500/40 border border-transparent',
}

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-2.5 text-xs gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  iconRight,
  className,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      className={cn(
        'inline-flex items-center justify-center rounded-lg font-medium transition-colors focus:outline-none focus-visible:ring-2 disabled:cursor-not-allowed disabled:opacity-50',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
    >
      {icon}
      {children}
      {iconRight}
    </button>
  )
}

/** Square icon-only button, used in toolbars and table action columns. */
export function IconButton({
  label,
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      {...rest}
      aria-label={label}
      title={label}
      className={cn(
        'inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/30 disabled:opacity-40',
        className,
      )}
    >
      {children}
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/* Inputs                                                                     */
/* -------------------------------------------------------------------------- */

interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  icon?: ReactNode
  /** Keyboard shortcut badge rendered on the right (e.g. ⌘K). */
  shortcut?: string
  wrapperClassName?: string
}

export function TextInput({
  icon,
  shortcut,
  className,
  wrapperClassName,
  ...rest
}: TextInputProps) {
  return (
    <div className={cn('relative', wrapperClassName)}>
      {icon ? (
        <span className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400">
          {icon}
        </span>
      ) : null}
      <input
        {...rest}
        className={cn(
          'h-9 w-full rounded-lg border border-slate-200 bg-white text-sm text-slate-900 outline-none transition-colors placeholder:text-slate-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-500/15 disabled:bg-slate-50',
          icon ? 'pl-8' : 'pl-3',
          shortcut ? 'pr-12' : 'pr-3',
          className,
        )}
      />
      {shortcut ? (
        <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] font-medium text-slate-400">
          {shortcut}
        </span>
      ) : null}
    </div>
  )
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  wrapperClassName?: string
}

export function Select({ className, wrapperClassName, children, ...rest }: SelectProps) {
  return (
    <div className={cn('relative', wrapperClassName)}>
      <select
        {...rest}
        className={cn(
          'h-9 w-full cursor-pointer appearance-none rounded-lg border border-slate-200 bg-white pl-3 pr-8 text-sm text-slate-700 outline-none transition-colors hover:bg-slate-50 focus:border-blue-400 focus:ring-2 focus:ring-blue-500/15',
          className,
        )}
      >
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
    </div>
  )
}

interface FieldProps {
  label: string
  hint?: ReactNode
  children: ReactNode
  htmlFor?: string
  className?: string
}

/** Labelled form row used across Settings and Grafana configuration. */
export function Field({ label, hint, children, htmlFor, className }: FieldProps) {
  return (
    <div className={cn('space-y-1.5', className)}>
      <label htmlFor={htmlFor} className="block text-xs font-medium text-slate-700">
        {label}
      </label>
      {children}
      {hint ? <p className="text-xs text-slate-400">{hint}</p> : null}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Toggle                                                                     */
/* -------------------------------------------------------------------------- */

interface ToggleProps {
  checked: boolean
  onChange: (next: boolean) => void
  label?: ReactNode
  description?: ReactNode
  disabled?: boolean
  id?: string
}

/** Accessible switch used for Grafana annotation levels and settings flags. */
export function Toggle({ checked, onChange, label, description, disabled, id }: ToggleProps) {
  return (
    <div className="flex items-start justify-between gap-4 py-2">
      {label || description ? (
        <div className="min-w-0">
          {label ? <p className="text-sm font-medium text-slate-800">{label}</p> : null}
          {description ? <p className="text-xs text-slate-500">{description}</p> : null}
        </div>
      ) : null}
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={typeof label === 'string' ? label : 'Toggle'}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 disabled:opacity-50',
          checked ? 'bg-blue-600' : 'bg-slate-300',
        )}
      >
        <span
          className={cn(
            'inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-xs transition-transform',
            checked ? 'translate-x-[1.15rem]' : 'translate-x-1',
          )}
        />
      </button>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Tabs                                                                       */
/* -------------------------------------------------------------------------- */

export interface TabItem<T extends string = string> {
  id: T
  label: string
  count?: number
}

interface TabsProps<T extends string> {
  tabs: TabItem<T>[]
  active: T
  onChange: (id: T) => void
  className?: string
}

/** Underlined tab strip (Google Workspace style). */
export function Tabs<T extends string>({ tabs, active, onChange, className }: TabsProps<T>) {
  return (
    <div className={cn('flex items-center gap-1 border-b border-slate-200', className)}>
      {(tabs ?? []).map((t) => {
        const on = t.id === active
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={cn(
              '-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium transition-colors',
              on
                ? 'border-blue-600 text-blue-700'
                : 'border-transparent text-slate-500 hover:border-slate-200 hover:text-slate-700',
            )}
          >
            {t.label}
            {typeof t.count === 'number' ? (
              <span
                className={cn(
                  'rounded-full px-1.5 text-[11px] tabular-nums',
                  on ? 'bg-blue-50 text-blue-700' : 'bg-slate-100 text-slate-500',
                )}
              >
                {t.count}
              </span>
            ) : null}
          </button>
        )
      })}
    </div>
  )
}

/** Small segmented control (e.g. chart granularity). */
export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  className,
}: {
  options: { id: T; label: string }[]
  value: T
  onChange: (v: T) => void
  className?: string
}) {
  return (
    <div className={cn('inline-flex rounded-lg border border-slate-200 bg-slate-50 p-0.5', className)}>
      {(options ?? []).map((o) => (
        <button
          key={o.id}
          onClick={() => onChange(o.id)}
          className={cn(
            'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
            o.id === value
              ? 'bg-white text-slate-900 shadow-xs'
              : 'text-slate-500 hover:text-slate-700',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
