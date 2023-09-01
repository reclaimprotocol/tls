export function delay(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

export function expectBuffsEq(a: Uint8Array, b: Uint8Array) {
	expect(
		Array.from(a)
	).toEqual(
		Array.from(b)
	)
}

/**
 * converts a space separated hex string to a buffer
 * @param txt eg. '01 02 03 04'
 */
export function bufferFromHexStringWithWhitespace(txt: string) {
	return Buffer.from(txt.replace(/\s/g, ''), 'hex')
}