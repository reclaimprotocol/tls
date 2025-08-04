import type { Logger } from '../types/index.ts'

export const logger: Logger = {
	info: console.info.bind(console),
	debug: console.debug.bind(console),
	trace: () => {},
	warn: console.warn.bind(console),
	error: console.error.bind(console),
}