import { crypto } from '../crypto'
import { getHash, getPrfHashAlgorithm, hkdfExtractAndExpandLabel } from '../utils/decryption-utils'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { areUint8ArraysEqual, concatenateUint8Arrays, strToUint8Array } from './generics'
import { packWith3ByteLength, packWithLength } from './packets'

type VerifyFinishMessageOptions = {
	secret: Uint8Array
	handshakeMessages: Uint8Array[]
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export async function verifyFinishMessage(
	verifyData: Uint8Array,
	opts: VerifyFinishMessageOptions
) {
	const computedData = await computeFinishMessageHash(opts)
	if(!areUint8ArraysEqual(computedData, verifyData)) {
		throw new Error('Invalid finish message')
	}
}

export async function packFinishMessagePacket(opts: VerifyFinishMessageOptions) {
	const hash = await computeFinishMessageHash(opts)
	const packet = concatenateUint8Arrays([
		new Uint8Array([ SUPPORTED_RECORD_TYPE_MAP.FINISHED, 0x00 ]),
		packWithLength(hash)
	])

	return packet
}

async function computeFinishMessageHash({
	secret, handshakeMessages, cipherSuite
}: VerifyFinishMessageOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const handshakeHash = await getHash(handshakeMessages, cipherSuite)
	const finishKey = await hkdfExtractAndExpandLabel(hashAlgorithm, secret, 'finished', new Uint8Array(0), hashLength)
	const hmacKey = await crypto.importKey(hashAlgorithm, finishKey)
	return crypto.hmac(hashAlgorithm, hmacKey, handshakeHash)
}

const TLS12_CLIENT_FINISH_DATA_LABEL = strToUint8Array('client finished')
const TLS12_SERVER_FINISH_DATA_LABEL = strToUint8Array('server finished')

export async function packClientFinishTls12(opts: VerifyFinishMessageOptions) {
	return concatenateUint8Arrays([
		new Uint8Array([ SUPPORTED_RECORD_TYPE_MAP.FINISHED ]),
		packWith3ByteLength(await generateFinishTls12('client', opts))
	])
}

export async function generateFinishTls12(
	type: 'client' | 'server',
	{ secret, handshakeMessages, cipherSuite }: VerifyFinishMessageOptions
) {
	// all key derivation in TLS 1.2 uses SHA-256
	const hashAlgorithm = getPrfHashAlgorithm(cipherSuite)
	const handshakeHash = await crypto.hash(
		hashAlgorithm,
		concatenateUint8Arrays(handshakeMessages)
	)
	const seed = concatenateUint8Arrays([
		type === 'client'
			? TLS12_CLIENT_FINISH_DATA_LABEL
			: TLS12_SERVER_FINISH_DATA_LABEL,
		handshakeHash
	])
	const key = await crypto.importKey(hashAlgorithm, secret)
	const a1 = await crypto.hmac(hashAlgorithm, key, seed)
	const p1 = await crypto.hmac(
		hashAlgorithm,
		key,
		concatenateUint8Arrays([ a1, seed ])
	)

	return p1.slice(0, 12)
}