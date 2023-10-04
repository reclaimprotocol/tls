import { AuthenticatedSymmetricCryptoAlgorithm, SymmetricCryptoAlgorithm } from '../types'

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
		result[i] = a[i]! ^ b[i]!
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

export function generateIV(iv: Uint8Array, recordNumber: number) {
	// make the recordNumber a buffer, so we can XOR with the main IV
	// to generate the specific IV to decrypt this packet
	const recordBuffer = new Uint8Array(iv.length)
	const recordBufferView = new DataView(recordBuffer.buffer)
	recordBufferView.setUint32(iv.length - 4, recordNumber)
	return xor(iv, recordBuffer)
}

/**
 * TLS has this special sort of padding where the last byte
 * is the number of padding bytes, and all the padding bytes
 * are the same as the last byte.
 * Eg. for an 8 byte block [ 0x0a, 0x0b, 0x0c, 0xd ]
 * -> [ 0x0a, 0x0b, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x04 ]
 */
export function padTls(data: Uint8Array, blockSize: number) {
	const nextMultiple = data.length % blockSize === 0
		? data.length + blockSize
		: Math.ceil(data.length / blockSize) * blockSize
	const paddingLength = nextMultiple - data.length
	if(!paddingLength) {
		return data
	}

	const paddingNum = paddingLength - 1
	const padded = new Uint8Array(nextMultiple)
	padded.set(data)
	padded.fill(paddingNum, data.length)
	padded.fill(paddingNum, nextMultiple - 1)
	return padded
}

export function isSymmetricCipher(
	cipher: SymmetricCryptoAlgorithm | AuthenticatedSymmetricCryptoAlgorithm
): cipher is SymmetricCryptoAlgorithm {
	return cipher === 'AES-128-CBC'
}