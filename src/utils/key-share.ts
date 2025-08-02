import { crypto } from '../crypto'
import { Key, TLSProtocolVersion, X509Certificate } from '../types'
import { SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_RECORD_TYPE_MAP, SUPPORTED_SIGNATURE_ALGS_MAP, TLS_PROTOCOL_VERSION_MAP } from './constants'
import { areUint8ArraysEqual, concatenateUint8Arrays } from './generics'
import { expectReadWithLength, packWith3ByteLength, packWithLength } from './packets'

export async function packClientCurveKeyShare(publicKey: Key) {
	return concatenateUint8Arrays([
		new Uint8Array([SUPPORTED_RECORD_TYPE_MAP['CLIENT_KEY_SHARE']]),
		packWith3ByteLength(
			// pack with 1 byte length
			packWithLength(await crypto.exportKey(publicKey)).slice(1)
		)
	])
}

export async function packClientRsaKeyShare(encPreMaster: Uint8Array) {
	return concatenateUint8Arrays([
		new Uint8Array([SUPPORTED_RECORD_TYPE_MAP['CLIENT_KEY_SHARE']]),
		packWith3ByteLength(packWithLength(encPreMaster))
	])
}

export async function processServerKeyShare(data: Uint8Array) {
	const type = read(1)[0]
	if(type !== 0x03) {
		throw new Error('expected "named_group" key share')
	}

	const curveTypeBytes = read(2)
	const curveTypeEntry = Object.entries(SUPPORTED_NAMED_CURVE_MAP)
		.find(([, { identifier }]) => areUint8ArraysEqual(identifier, curveTypeBytes))
	if(!curveTypeEntry) {
		throw new Error(`unsupported curve type: ${curveTypeBytes}`)
	}

	const publicKeyType = curveTypeEntry[0] as keyof typeof SUPPORTED_NAMED_CURVE_MAP
	const publicKeyBytes = readWLength(1)

	const publicKey = await crypto.importKey(
		curveTypeEntry[1].algorithm,
		publicKeyBytes,
		'public'
	)

	const signatureTypeBytes = read(2)
	const signatureTypeEntry = Object.entries(SUPPORTED_SIGNATURE_ALGS_MAP)
		.find(([, { identifier }]) => areUint8ArraysEqual(identifier, signatureTypeBytes))
	if(!signatureTypeEntry) {
		throw new Error(`unsupported signature type: ${signatureTypeBytes}`)
	}

	const signatureAlgorithm = signatureTypeEntry[0] as keyof typeof SUPPORTED_SIGNATURE_ALGS_MAP
	const signatureBytes = readWLength(2)

	return {
		publicKeyType,
		publicKey,
		signatureAlgorithm,
		signatureBytes,
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

export async function createRsaPreMasterSecret(
	serverCert: X509Certificate,
	tlsVersion: TLSProtocolVersion,
	rand: Uint8Array = crypto.randomBytes(46)
) {
	const preMasterSecret = concatenateUint8Arrays([
		TLS_PROTOCOL_VERSION_MAP[tlsVersion],
		rand
	])

	const servPubKey = serverCert.getPublicKey()
	if(servPubKey.algorithm !== 'RSASSA-PKCS1-v1_5') {
		throw new Error(
			`expected RSASSA-PKCS1-v1_5 cert, got ${servPubKey.algorithm}`
		)
	}

	const publicKey = await crypto
		.importKey('RSA-PCKS1_5', servPubKey.buffer, 'public')
	const rslt = await crypto
		.asymmetricEncrypt('RSA-PCKS1_5', { data: preMasterSecret, publicKey })
	return { preMasterSecret, encrypted: rslt }
}