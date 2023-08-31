/**
 * Converts a buffer to a hex string with whitespace between each byte
 * @returns eg. '01 02 03 04'
 */
export function toHexStringWithWhitespace(buff: Buffer) {
	let hex = buff.toString('hex')
	let i = 2
	while(i < hex.length) {
		hex = hex.slice(0, i) + ' ' + hex.slice(i)
		i += 3
	}

	return hex
}

/**
 * converts a space separated hex string to a buffer
 * @param txt eg. '01 02 03 04'
 */
export function bufferFromHexStringWithWhitespace(txt: string) {
	return Buffer.from(txt.replace(/\s/g, ''), 'hex')
}

export function xor(a: Uint8Array, b: Uint8Array) {
	const result = Buffer.alloc(a.length)
	for(let i = 0; i < a.length; i++) {
		result[i] = a[i] ^ b[i]
	}

	return result
}
