import { createHmac } from 'crypto'
import { getHash, hkdfExtractAndExpandLabel } from '../utils/decryption-utils'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_RECORD_TYPE_MAP } from './constants'
import { packWithLength } from './packets'

type VerifyFinishMessageOptions = {
	secret: Buffer
	handshakeMessages: Buffer[]
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export function verifyFinishMessage(
	verifyData: Buffer,
	opts: VerifyFinishMessageOptions
) {
	const computedData = computeFinishMessageHash(opts)

	if(!computedData.equals(verifyData)) {
		throw new Error('Invalid finish message')
	}
}

export function packFinishMessagePacket(opts: VerifyFinishMessageOptions) {
	const hash = computeFinishMessageHash(opts)
	const packet = Buffer.concat([
		Buffer.from([ SUPPORTED_RECORD_TYPE_MAP.FINISHED, 0x00 ]),
		packWithLength(hash)
	])

	return packet
}

function computeFinishMessageHash({
	secret, handshakeMessages, cipherSuite
}: VerifyFinishMessageOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const handshakeHash = getHash(handshakeMessages, cipherSuite)

	const finishKey = hkdfExtractAndExpandLabel(hashAlgorithm, secret, 'finished', Buffer.alloc(0), hashLength)
	const computedData = createHmac(hashAlgorithm, finishKey).update(handshakeHash).digest()

	return computedData
}