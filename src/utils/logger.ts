import type { Logger } from '../types/index.ts'

export const logger: Logger = {
	info(...args) {
		return console.info(...args)
	},
	debug(...args) {
		return console.debug(...args)
	},
	trace: () => {},
	warn(...args) {
		return console.warn(...args)
	},
	error(...args) {
		return console.error(...args)
	}
}