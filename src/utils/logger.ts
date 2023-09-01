import { Logger } from '../types'

export const logger: Logger = {
	info: console.info.bind(console),
	debug: console.debug.bind(console),
	trace: () => {},
	warn: console.warn.bind(console),
	error: console.error.bind(console),
}