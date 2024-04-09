import { crypto } from '../crypto'
import { TLSProtocolVersion } from '../types'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_CIPHER_SUITES, SUPPORTED_EXTENSION_MAP, SUPPORTED_EXTENSIONS, SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_NAMED_CURVES, TLS_PROTOCOL_VERSION_MAP } from './constants'
import { areUint8ArraysEqual, uint8ArrayToDataView, uint8ArrayToStr } from './generics'
import { expectReadWithLength } from './packets'

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

	const extensionsLength = uint8ArrayToDataView(read(2)).getUint16(0)
	let publicKey: Uint8Array | undefined
	let publicKeyType: keyof typeof SUPPORTED_NAMED_CURVE_MAP | undefined
	let supportsPsk = false
	let serverTlsVersion: TLSProtocolVersion = 'TLS1_2'
	let maxFragmentLengthBytes: number | undefined
	let selectedAlpn: string | undefined

	if(extensionsLength) {
		while(data.length) {
			const { type, extData } = readExtension()
			switch (type) {
			case 'ALPN':
				const data = expectReadWithLength(extData)
				const alpnBytes = expectReadWithLength(data, 1)
				selectedAlpn = uint8ArrayToStr(alpnBytes)
				console.log('ALPN', selectedAlpn)
				break
			case 'SUPPORTED_VERSIONS':
				const supportedV = Object.entries(TLS_PROTOCOL_VERSION_MAP)
					.find(([, v]) => areUint8ArraysEqual(v, extData))
				if(!supportedV) {
					throw new Error(`Unsupported TLS version '${extData}'`)
				}

				serverTlsVersion = supportedV[0] as TLSProtocolVersion

				break
			case 'KEY_SHARE':
				const typeBytes = extData.slice(0, 2)
				publicKeyType = SUPPORTED_NAMED_CURVES
					.find(k => areUint8ArraysEqual(SUPPORTED_NAMED_CURVE_MAP[k].identifier, typeBytes))
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

	if(
		serverTlsVersion === 'TLS1_3'
		&& (!publicKey || !publicKeyType)
	) {
		throw new Error('Missing key share in TLS 1.3')
	}

	return {
		serverTlsVersion,
		serverRandom,
		sessionId,
		cipherSuite,
		supportsPsk,
		maxFragmentLengthBytes,
		selectedAlpn,
		...(
			publicKey && publicKeyType
				? {
					publicKey: await crypto.importKey(
						SUPPORTED_NAMED_CURVE_MAP[publicKeyType].algorithm,
						publicKey,
						'public'
					),
					publicKeyType,
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

	function readExtension() {
		const typeByte = read(2)[1]
		const extData = readWLength(2)
		const type = SUPPORTED_EXTENSIONS
			.find(k => SUPPORTED_EXTENSION_MAP[k] === typeByte)

		return { type, extData }
	}
}