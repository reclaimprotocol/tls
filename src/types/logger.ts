
type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'trace'

type LogFn = (...args: any[]) => void

export type Logger = { [L in LogLevel]: LogFn }