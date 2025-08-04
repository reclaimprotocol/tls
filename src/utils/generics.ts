import type { AuthenticatedSymmetricCryptoAlgorithm, Crypto, HashAlgorithm, Key, SymmetricCryptoAlgorithm, TLSProtocolVersion } from '../types/index.ts'
import { TLS_PROTOCOL_VERSION_MAP } from './constants.ts'

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
	for(const [i, element] of a.entries()) {
		result[i] = element ^ b[i]
	}

	return result
}

export function concatenateUint8Arrays(
	arrays: Uint8Array[]
): Uint8Array {
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

	for(const [i, element] of a.entries()) {
		if(element !== b[i]) {
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

export function uint8ArrayToStr(arr: Uint8Array) {
	return new TextDecoder().decode(arr)
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

	const paddingNum = paddingLength - 1
	const padded = new Uint8Array(nextMultiple)
	padded.set(data)
	padded.fill(paddingNum, data.length)
	padded.fill(paddingNum, nextMultiple - 1)
	return padded
}

/**
 * Unpad a TLS-spec padded buffer
 */
export function unpadTls(data: Uint8Array) {
	const paddingLength = data[data.length - 1]
	for(let i = 0; i < paddingLength; i++) {
		if(data[data.length - 1 - i] !== paddingLength) {
			throw new Error('Invalid padding')
		}
	}

	return data.slice(0, data.length - paddingLength)
}

export function isSymmetricCipher(
	cipher: SymmetricCryptoAlgorithm | AuthenticatedSymmetricCryptoAlgorithm
): cipher is SymmetricCryptoAlgorithm {
	return cipher === 'AES-128-CBC'
}

export function chunkUint8Array(arr: Uint8Array, chunkSize: number) {
	const result: Uint8Array[] = []
	for(let i = 0; i < arr.length; i += chunkSize) {
		result.push(arr.slice(i, i + chunkSize))
	}

	return result
}

export function getTlsVersionFromBytes(bytes: Uint8Array) {
	const supportedV = Object.entries(TLS_PROTOCOL_VERSION_MAP)
		.find(([, v]) => areUint8ArraysEqual(v, bytes))
	if(!supportedV) {
		throw new Error(`Unsupported TLS version '${bytes}'`)
	}

	return supportedV[0] as TLSProtocolVersion
}

export const hkdfExpand = async(
	alg: HashAlgorithm,
	hashLength: number,
	key: Key,
	expLength: number,
	info: Uint8Array,
	crypto: Crypto<unknown>
) => {
	info ||= new Uint8Array(0)
	const infoLength = info.length
	const steps = Math.ceil(expLength / hashLength)
	if(steps > 0xFF) {
		throw new Error(`OKM length ${expLength} is too long for ${alg} hash`)
	}

	// use single buffer with unnecessary create/copy/move operations
	const t = new Uint8Array(hashLength * steps + infoLength + 1)
	for(let c = 1, start = 0, end = 0; c <= steps; ++c) {
		// add info
		t.set(info, end)
		// add counter
		t.set([c], end + infoLength)
		// use view: T(C) = T(C-1) | info | C
		const hmac = await crypto
			.hmac(alg, key, t.slice(start, end + infoLength + 1))
		// put back to the same buffer
		t.set(hmac.slice(0, t.length - end), end)

		start = end // used for T(C-1) start
		end += hashLength // used for T(C-1) end & overall end
	}

	return t.slice(0, expLength)
}