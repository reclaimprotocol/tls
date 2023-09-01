/**
 * Converts a buffer to a hex string with whitespace between each byte
 * @returns eg. '01 02 03 04'
 */
export function toHexStringWithWhitespace(buff: Uint8Array, whitespace = ' ') {
	return [...buff]
		.map(x => x.toString(16).padStart(2, '0'))
		.join(whitespace)
}

export function xor(a: Uint8Array, b: Uint8Array) {
	const result = new Uint8Array(a.length)
	for(let i = 0; i < a.length; i++) {
		result[i] = a.at(i)! ^ b.at(i)!
	}

	return result
}

export function concatenateUint8Arrays(arrays: Uint8Array[]) {
	const totalLength = arrays.reduce((acc, curr) => acc + curr.length, 0)
	const result = new Uint8Array(totalLength)
	let offset = 0
	for(const arr of arrays) {
		result.set(arr, offset)
		offset += arr.length
	}

	return result
}

export function areUint8ArraysEqual(a: Uint8Array, b: Uint8Array) {
	if(a.length !== b.length) {
		return false
	}

	for(let i = 0; i < a.length; i++) {
		if(a[i] !== b[i]) {
			return false
		}
	}

	return true
}

export function uint8ArrayToDataView(arr: Uint8Array) {
	return new DataView(arr.buffer, arr.byteOffset, arr.byteLength)
}

export function strToUint8Array(str: string) {
	return new TextEncoder().encode(str)
}