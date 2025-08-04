import assert from 'node:assert'
import { pino } from 'pino'

export function delay(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

export function expectBuffsEq(a: Uint8Array, b: Uint8Array) {
	assert.deepEqual(Array.from(a), Array.from(b))
}

/**
 * converts a space separated hex string to a buffer
 * @param txt eg. '01 02 03 04'
 */
export function bufferFromHexStringWithWhitespace(txt: string) {
	return Buffer.from(txt.replace(/\s/g, ''), 'hex')
}

export const logger = pino({})
logger.level = process.env.LOG_LEVEL || 'info'