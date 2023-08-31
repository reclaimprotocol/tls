import { createHmac } from 'crypto'
import { getHash, hkdfExtractAndExpandLabel } from '../utils/decryption-utils'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { packWithLength } from './packets'
import { concatenateUint8Arrays } from './generics'

type VerifyFinishMessageOptions = {
	secret: Uint8Array
	handshakeMessages: Uint8Array[]
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export function verifyFinishMessage(
	verifyData: Uint8Array,
	opts: VerifyFinishMessageOptions
) {
	const computedData = computeFinishMessageHash(opts)

	if(!computedData.equals(verifyData)) {
		throw new Error('Invalid finish message')
	}
}

export function packFinishMessagePacket(opts: VerifyFinishMessageOptions) {
	const hash = computeFinishMessageHash(opts)
	const packet = concatenateUint8Arrays([
		new Uint8Array([ SUPPORTED_RECORD_TYPE_MAP.FINISHED, 0x00 ]),
		packWithLength(hash)
	])

	return packet
}

function computeFinishMessageHash({
	secret, handshakeMessages, cipherSuite
}: VerifyFinishMessageOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const handshakeHash = getHash(handshakeMessages, cipherSuite)

	const finishKey = hkdfExtractAndExpandLabel(hashAlgorithm, secret, 'finished', new Uint8Array(0), hashLength)
	const computedData = createHmac(hashAlgorithm, finishKey).update(handshakeHash).digest()

	return computedData
}