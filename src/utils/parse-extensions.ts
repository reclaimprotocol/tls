import { SupportedExtensionServerData, TLSProtocolVersion } from '../types'
import { SUPPORTED_EXTENSION_MAP, SUPPORTED_EXTENSIONS, SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_NAMED_CURVES, TLS_PROTOCOL_VERSION_MAP } from './constants'
import { areUint8ArraysEqual, uint8ArrayToStr } from './generics'
import { expectReadWithLength } from './packets'

type ParseExtensionFn<T extends keyof SupportedExtensionServerData> = (
	(data: Uint8Array) => SupportedExtensionServerData[T]
)

const EXTENSION_PARSERS: { [K in keyof SupportedExtensionServerData]: ParseExtensionFn<K> } = {
	'ALPN': (extData) => {
		const data = expectReadWithLength(extData)
		const alpnBytes = expectReadWithLength(data, 1)
		return uint8ArrayToStr(alpnBytes)
	},
	'SUPPORTED_VERSIONS': (extData) => {
		const supportedV = Object.entries(TLS_PROTOCOL_VERSION_MAP)
			.find(([, v]) => areUint8ArraysEqual(v, extData))
		if(!supportedV) {
			throw new Error(`Unsupported TLS version '${extData}'`)
		}

		return supportedV[0] as TLSProtocolVersion
	},
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
}

/**
 * Parse a length-encoded list of extensions
 */
export function parseExtensions(data: Uint8Array) {
	data = readWLength(2)

	const map: Partial<SupportedExtensionServerData> = {}
	const seenExtensions = new Set<number>()
	while(data.length) {
		const typeByte = read(2)[1]
		const extData = readWLength(2)
		const type = SUPPORTED_EXTENSIONS
			.find(k => SUPPORTED_EXTENSION_MAP[k] === typeByte)
		if(seenExtensions.has(typeByte)) {
			throw new Error(`Duplicate extension '${type}' (${typeByte})`)
		}

		if(type && type in EXTENSION_PARSERS) {
			map[type] = EXTENSION_PARSERS[type](extData)
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