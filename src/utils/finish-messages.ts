import { crypto } from '../crypto'
import { getHash, hkdfExtractAndExpandLabel } from '../utils/decryption-utils'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { areUint8ArraysEqual, concatenateUint8Arrays } from './generics'
import { packWithLength } from './packets'

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