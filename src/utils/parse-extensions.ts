import { SupportedExtensionClientData, SupportedExtensionServerData } from '../types'
import { SUPPORTED_EXTENSION_MAP, SUPPORTED_EXTENSIONS, SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_NAMED_CURVES } from './constants'
import { areUint8ArraysEqual, getTlsVersionFromBytes, uint8ArrayToStr } from './generics'
import { expectReadWithLength } from './packets'

/**
 * Parse a length-encoded list of extensions
 * sent by the server
 */
export function parseServerExtensions(data: Uint8Array) {
	return parseExtensions<SupportedExtensionServerData>(data, {
		'ALPN': (extData) => {
			const data = expectReadWithLength(extData)
			const alpnBytes = expectReadWithLength(data, 1)
			return uint8ArrayToStr(alpnBytes)
		},
		'SUPPORTED_VERSIONS': getTlsVersionFromBytes,
		'PRE_SHARED_KEY': () => ({ supported: true }),
		'KEY_SHARE': (extData) => {
			const typeBytes = extData.slice(0, 2)
			const type = SUPPORTED_NAMED_CURVES
				.find(k => areUint8ArraysEqual(SUPPORTED_NAMED_CURVE_MAP[k].identifier, typeBytes))
			if(!type) {
				throw new Error(`Unsupported key type '${typeBytes}'`)
			}

			const publicKey = expectReadWithLength(extData.slice(2))
			return { type, publicKey }
		}
	})
}

/**
 * Parse a length-encoded list of extensions
 * sent by the client
 */
export function parseClientExtensions(data: Uint8Array) {
	return parseExtensions<SupportedExtensionClientData>(data, {
		'SERVER_NAME': (extData) => {
			extData = expectReadWithLength(extData)
			const byte = extData[0]
			extData = extData.slice(1)
			const serverNameBytes = expectReadWithLength(extData)
			return {
				type: byte,
				serverName: uint8ArrayToStr(serverNameBytes)
			}
		}
	})
}

function parseExtensions<T extends SupportedExtensionServerData | SupportedExtensionClientData>(
	data: Uint8Array,
	parsers: { [K in keyof T]: ((data: Uint8Array) => T[K]) }
) {
	data = readWLength(2)

	const map: Partial<T> = {}
	const seenExtensions = new Set<number>()
	while(data.length) {
		const typeByte = read(2)[1]
		const extData = readWLength(2)
		const type = SUPPORTED_EXTENSIONS
			.find(k => SUPPORTED_EXTENSION_MAP[k] === typeByte)
		if(seenExtensions.has(typeByte)) {
			throw new Error(`Duplicate extension '${type}' (${typeByte})`)
		}

		if(type && type in parsers) {
			map[type] = parsers[type](extData)
		}
	}

	return map

	function read(bytes: number) {
		const result = data.slice(0, bytes)
		data = data.slice(bytes)
		return result
	}

	function readWLength(bytesLength = 2) {
		const content = expectReadWithLength(data, bytesLength)
		data = data.slice(content.length + bytesLength)

		return content
	}
}