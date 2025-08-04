import { crypto } from '../crypto/index.ts'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_CIPHER_SUITES, SUPPORTED_NAMED_CURVE_MAP } from './constants.ts'
import { areUint8ArraysEqual } from './generics.ts'
import { expectReadWithLength } from './packets.ts'
import { parseServerExtensions } from './parse-extensions.ts'

export async function parseServerHello(data: Uint8Array) {
	// header TLS version (expected to be 0x0303)
	read(2)
	const serverRandom = read(32)
	const sessionId = readWLength(1)

	const cipherSuiteBytes = read(2)

	const cipherSuite = SUPPORTED_CIPHER_SUITES
		.find(k => areUint8ArraysEqual(SUPPORTED_CIPHER_SUITE_MAP[k].identifier, cipherSuiteBytes))
	if(!cipherSuite) {
		throw new Error(`Unsupported cipher suite '${cipherSuiteBytes}'`)
	}

	const compressionMethod = read(1)[0]
	if(compressionMethod !== 0x00) {
		throw new Error(`Unsupported compression method '${compressionMethod.toString(16)}'`)
	}

	const extensions = parseServerExtensions(data)
	const serverTlsVersion = extensions['SUPPORTED_VERSIONS'] || 'TLS1_2'
	const pubKeyExt = extensions['KEY_SHARE']

	if(
		serverTlsVersion === 'TLS1_3'
		&& !pubKeyExt
	) {
		throw new Error('Missing key share in TLS 1.3')
	}

	return {
		serverTlsVersion,
		serverRandom,
		sessionId,
		cipherSuite,
		supportsPsk: !!extensions['PRE_SHARED_KEY']?.supported,
		extensions,
		...(
			pubKeyExt
				? {
					publicKey: await crypto.importKey(
						SUPPORTED_NAMED_CURVE_MAP[pubKeyExt.type].algorithm,
						pubKeyExt.publicKey,
						'public'
					),
					publicKeyType: pubKeyExt.type,
				}
				: {}
		)
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