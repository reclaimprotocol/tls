import assert from 'node:assert'
import type { Mock } from 'node:test'
import { setTimeout } from 'node:timers/promises'
import { pino } from 'pino'

export const delay = setTimeout

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

export async function waitForMockCall<T extends Function>(
	{ mock }: Mock<T>,
	timeoutMs = 5000
) {
	const start = Date.now()
	while(!mock.calls.length) {
		if(Date.now() - start > timeoutMs) {
			throw new Error('Timed out waiting for mock call')
		}

		await delay(100)
	}
}

export const logger = pino({})
logger.level = process.env.LOG_LEVEL || 'info'