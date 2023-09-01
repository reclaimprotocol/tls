import { crypto } from '../crypto'
import { CURRENT_PROTOCOL_VERSION, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_CIPHER_SUITES, SUPPORTED_EXTENSION_MAP, SUPPORTED_EXTENSIONS, SUPPORTED_KEY_TYPE_MAP, SUPPORTED_KEY_TYPES } from './constants'
import { areUint8ArraysEqual, uint8ArrayToDataView } from './generics'
import { expectReadWithLength } from './packets'

export async function parseServerHello(data: Uint8Array) {
	const serverVersion = read(2)
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
	
	const extensionsLength = uint8ArrayToDataView(read(2)).getUint16(0)
	let publicKey: Uint8Array | undefined
	let publicKeyType: keyof typeof SUPPORTED_KEY_TYPE_MAP | undefined
	let supportsPsk = false

	if(extensionsLength) {
		while(data.length) {
			const { type, extData } = readExtension()
			switch (type) {
			case 'SUPPORTED_VERSIONS':
				if(!areUint8ArraysEqual(CURRENT_PROTOCOL_VERSION, extData)) {
					throw new Error(`Server does not support TLS version. Version recv: '${extData}'`)
				}

				break
			case 'KEY_SHARE':
				const typeBytes = extData.slice(0, 2)
				publicKeyType = SUPPORTED_KEY_TYPES
					.find(k => areUint8ArraysEqual(SUPPORTED_KEY_TYPE_MAP[k].identifier, typeBytes))
				if(!publicKeyType) {
					throw new Error(`Unsupported key type '${typeBytes}'`)
				}

				publicKey = expectReadWithLength(extData.slice(2))

				break
			case 'PRE_SHARED_KEY':
				supportsPsk = true
				break
			}
		}
	}

	if(!publicKey || !publicKeyType) {
		throw new Error('Server did not send a public key')
	}

	return {
		serverVersion,
		serverRandom,
		sessionId,
		cipherSuite,
		publicKey: await crypto.importKey(
			SUPPORTED_KEY_TYPE_MAP[publicKeyType].algorithm,
			publicKey,
			'public'
		),
		publicKeyType,
		supportsPsk
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

	function readExtension() {
		const typeByte = read(2)[1]
		const extData = readWLength(2)
		const type = SUPPORTED_EXTENSIONS
			.find(k => SUPPORTED_EXTENSION_MAP[k] === typeByte)

		return { type, extData }
	}
}