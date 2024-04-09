import { SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { getTlsVersionFromBytes } from './generics'
import { expectReadWithLength } from './packets'
import { parseClientExtensions } from './parse-extensions'

/**
 * Parse a full client hello message
 */
export function parseClientHello(data: Uint8Array) {
	const packetType = read(1)[0]
	if(packetType !== SUPPORTED_RECORD_TYPE_MAP.CLIENT_HELLO) {
		throw new Error(`Invalid record type for client hello (${packetType})`)
	}

	data = readWLength(3)
	const versionBytes = read(2)
	const version = getTlsVersionFromBytes(versionBytes)
	const serverRandom = read(32)
	const sessionId = readWLength(1)
	const cipherSuitesBytes = readWLength(2)
	const compressionMethodByte = readWLength(1)[0]
	const extensions = parseClientExtensions(data)

	return {
		version,
		serverRandom,
		sessionId,
		cipherSuitesBytes,
		compressionMethodByte,
		extensions,
	}

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