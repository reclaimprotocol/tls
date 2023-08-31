import { createHmac, randomBytes } from 'crypto'
import { TLSPresharedKey } from '../types'
import { getHash } from '../utils/decryption-utils'
import { COMPRESSION_MODE, CURRENT_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_EXTENSION_MAP, SUPPORTED_KEY_TYPE_MAP, SUPPORTED_RECORD_TYPE_MAP, SUPPORTED_SIGNATURE_ALGS_MAP } from './constants'
import { packWith3ByteLength, packWithLength } from './packets'
import { concatenateUint8Arrays, strToUint8Array, uint8ArrayToDataView } from './generics'

type SupportedKeyType = keyof typeof SUPPORTED_KEY_TYPE_MAP

type PublicKeyData = { type: SupportedKeyType, key: Uint8Array }

type ClientHelloOptions = {
	host: string
	keysToShare: PublicKeyData[]
	random?: Uint8Array
	sessionId?: Uint8Array
	psk?: TLSPresharedKey
	cipherSuites?: (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]
}

type ExtensionData = {
	type: keyof typeof SUPPORTED_EXTENSION_MAP
	data: Uint8Array
	/** number of bytes to use for length */
	lengthBytes?: number
}

export function packClientHello({
	host,
	sessionId,
	random,
	keysToShare,
	psk,
	cipherSuites,
}: ClientHelloOptions) {
	// generate random & sessionId if not provided
	random = random || randomBytes(32)
	sessionId = sessionId || randomBytes(32)

	const packedSessionId = packWithLength(sessionId).slice(1)
	const cipherSuiteList = (cipherSuites || Object.keys(SUPPORTED_CIPHER_SUITE_MAP))
		.map(cipherSuite => SUPPORTED_CIPHER_SUITE_MAP[cipherSuite].identifier)
	const packedCipherSuites = packWithLength(concatenateUint8Arrays(cipherSuiteList))
	const extensionsList = [
		packServerNameExtension(host),
		packSupportedGroupsExtension(),
		packSessionTicketExtension(),
		packVersionsExtension(),
		packSignatureAlgorithmsExtension(),
		packPresharedKeyModeExtension(),
		packKeyShareExtension(keysToShare)
	]

	if(psk) {
		extensionsList.push(packPresharedKeyExtension(psk))
	}

	const packedExtensions = packWithLength(concatenateUint8Arrays(extensionsList))

	const handshakeData = concatenateUint8Arrays([
		LEGACY_PROTOCOL_VERSION,
		random,
		packedSessionId,
		packedCipherSuites,
		COMPRESSION_MODE,
		packedExtensions
	])

	const packedHandshake = concatenateUint8Arrays([
		new Uint8Array([ SUPPORTED_RECORD_TYPE_MAP.CLIENT_HELLO ]),
		packWith3ByteLength(handshakeData)
	])

	if(psk) {
		const { hashLength } = SUPPORTED_CIPHER_SUITE_MAP[psk.cipherSuite]
		const prefixHandshake = packedHandshake.slice(0, - hashLength - 3)
		const binder = computeBinderSuffix(
			prefixHandshake,
			psk
		)
		binder.copy(packedHandshake, packedHandshake.length - binder.length)
	}

	return packedHandshake
}

export function computeBinderSuffix(packedHandshakePrefix: Uint8Array, psk: TLSPresharedKey) {
	const { hashAlgorithm } = SUPPORTED_CIPHER_SUITE_MAP[psk.cipherSuite]

	const hashedHelloHandshake = getHash([ packedHandshakePrefix ], psk.cipherSuite)

	const binder = createHmac(hashAlgorithm, psk.finishKey)
		.update(hashedHelloHandshake)
		.digest()
	return binder
}

/**
 * Packs the preshared key extension; the binder is assumed to be 0
 * The empty binder is suffixed to the end of the extension
 * and should be replaced with the correct binder after the full handshake is computed
 */
export function packPresharedKeyExtension({ identity, ticketAge, cipherSuite }: TLSPresharedKey) {
	const binderLength = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite].hashLength

	const packedIdentity = packWithLength(identity)
	const packedTicketAge = new Uint8Array(4)
	const packedTicketAgeView = uint8ArrayToDataView(packedTicketAge)
	packedTicketAgeView.setUint32(0, ticketAge)

	const serialisedIdentity = concatenateUint8Arrays([
		packedIdentity,
		packedTicketAge
	])
	const identityPacked = packWithLength(serialisedIdentity)
	const binderHolderBytes = new Uint8Array(binderLength + 2 + 1)
	const binderHolderBytesView = uint8ArrayToDataView(binderHolderBytes)
	binderHolderBytesView.setUint16(0, binderLength + 1)
	binderHolderBytesView.setUint8(2, binderLength)

	const total = concatenateUint8Arrays([
		identityPacked,
		// 2 bytes for binders
		// 1 byte for each binder length
		binderHolderBytes
	])
	const totalPacked = packWithLength(total)

	const ext = new Uint8Array(2 + totalPacked.length)
	ext.set(totalPacked, 2)
	const extView = uint8ArrayToDataView(ext)
	extView.setUint16(0, SUPPORTED_EXTENSION_MAP.PRE_SHARED_KEY)

	return ext
}

function packPresharedKeyModeExtension() {
	return packExtension({
		type: 'PRE_SHARED_KEY_MODE',
		data: new Uint8Array([ 0x00, 0x01 ]),
		lengthBytes: 1
	})
}

function packSessionTicketExtension() {
	return packExtension({
		type: 'SESSION_TICKET',
		data: new Uint8Array(),
	})
}

function packVersionsExtension() {
	return packExtension({
		type: 'SUPPORTED_VERSIONS',
		data: CURRENT_PROTOCOL_VERSION,
		lengthBytes: 1
	})
}

function packSignatureAlgorithmsExtension() {
	return packExtension({
		type: 'SIGNATURE_ALGS',
		data: concatenateUint8Arrays(
			Object.values(SUPPORTED_SIGNATURE_ALGS_MAP)
				.map(v => v.identifier)
		)
	})
}

function packSupportedGroupsExtension() {
	return packExtension({
		type: 'SUPPORTED_GROUPS',
		data: concatenateUint8Arrays(
			Object.values(SUPPORTED_KEY_TYPE_MAP)
		)
	})
}

function packKeyShareExtension(keys: PublicKeyData[]) {
	const buffs: Uint8Array[] = []
	for(const { key, type } of keys) {
		buffs.push(
			SUPPORTED_KEY_TYPE_MAP[type],
			packWithLength(key)
		)
	}

	return packExtension({
		type: 'KEY_SHARE',
		data: concatenateUint8Arrays(buffs)
	})
}

function packServerNameExtension(host: string) {
	return packExtension({
		type: 'SERVER_NAME',
		data: concatenateUint8Arrays([
			// specify that this is a server hostname
			new Uint8Array([ 0x0 ]),
			// pack the remaining data prefixed with length
			packWithLength(strToUint8Array(host))
		])
	})
}

function packExtension({ type, data, lengthBytes }: ExtensionData) {
	lengthBytes = lengthBytes || 2
	let packed = data.length ? packWithLength(data) : data
	if(lengthBytes === 1) {
		packed = packed.slice(1)
	}

	// 2 bytes for type, 2 bytes for packed data length
	const result = new Uint8Array(2 + 2 + packed.length)
	const resultView = uint8ArrayToDataView(result)
	resultView.setUint8(1, SUPPORTED_EXTENSION_MAP[type])
	resultView.setUint16(2, packed.length)
	result.set(packed, 4)

	return result
}