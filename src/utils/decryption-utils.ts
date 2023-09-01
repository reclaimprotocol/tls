import { SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { packWithLength } from './packets'
import { HashAlgorithm } from '../types'
import { concatenateUint8Arrays, strToUint8Array, uint8ArrayToDataView } from './generics'
import { crypto } from '../crypto'

type DeriveTrafficKeysOptions = {
	masterSecret: Uint8Array
	/** used to derive keys when resuming session */
	earlySecret?: Uint8Array

	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
	/** list of handshake message to hash; or the hash itself */
	hellos: Uint8Array[] | Uint8Array
	/** type of secret; handshake or provider-data */
	secretType: 'hs' | 'ap'
}

export type SharedKeyData = Awaited<ReturnType<typeof computeSharedKeys>>

export function computeUpdatedTrafficMasterSecret(
	masterSecret: Uint8Array,
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	return hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'traffic upd', new Uint8Array(), hashLength)
}

export async function computeSharedKeys({
	hellos,
	masterSecret: masterKey,
	cipherSuite,
	secretType,
	earlySecret
}: DeriveTrafficKeysOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

	const emptyHash = await crypto.hash(hashAlgorithm, new Uint8Array())
	const zeros = new Uint8Array(hashLength)
	let handshakeTrafficSecret: Uint8Array
	if(secretType === 'hs') {
		// some hashes
		earlySecret = earlySecret
			|| await crypto.extract(hashAlgorithm, hashLength, zeros, '')
		const derivedSecret = await hkdfExtractAndExpandLabel(hashAlgorithm, earlySecret, 'derived', emptyHash, hashLength)

		handshakeTrafficSecret = await crypto.extract(hashAlgorithm, hashLength, Buffer.from(masterKey), derivedSecret)
	} else {
		const derivedSecret = await hkdfExtractAndExpandLabel(hashAlgorithm, masterKey, 'derived', emptyHash, hashLength)
		handshakeTrafficSecret = await crypto.extract(hashAlgorithm, hashLength, Buffer.from(zeros), derivedSecret)
	}

	return deriveTrafficKeys({
		hellos,
		cipherSuite,
		masterSecret: handshakeTrafficSecret,
		secretType
	})
}

export async function deriveTrafficKeys({
	masterSecret,
	cipherSuite,
	hellos,
	secretType,
}: DeriveTrafficKeysOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

	const handshakeHash = await getHash(hellos, cipherSuite)
	const clientSecret = await hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, `c ${secretType} traffic`, handshakeHash, hashLength)
	const serverSecret = await hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, `s ${secretType} traffic`, handshakeHash, hashLength)
	const { encKey: clientEncKey, iv: clientIv } = await deriveTrafficKeysForSide(clientSecret, cipherSuite)
	const { encKey: serverEncKey, iv: serverIv } = await deriveTrafficKeysForSide(serverSecret, cipherSuite)

	return {
		masterSecret,
		clientSecret,
		serverSecret,
		clientEncKey,
		serverEncKey,
		clientIv,
		serverIv
	}
}

export async function deriveTrafficKeysForSide(masterSecret: Uint8Array, cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP) {
	const { hashAlgorithm, keyLength, cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const ivLen = 12

	const encKey = await hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'key', new Uint8Array(), keyLength)
	const iv = await hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'iv', new Uint8Array(0), ivLen)

	return {
		masterSecret,
		encKey: await crypto.importKey(encKey, cipher),
		iv
	}
}

export function hkdfExtractAndExpandLabel(algorithm: HashAlgorithm, key: Uint8Array, label: string, context: Uint8Array, length: number) {
	const tmpLabel = `tls13 ${label}`
	const lengthBuffer = new Uint8Array(2)
	const lengthBufferView = uint8ArrayToDataView(lengthBuffer)
	lengthBufferView.setUint16(0, length)
	const hkdfLabel = concatenateUint8Arrays([
		lengthBuffer,
		packWithLength(strToUint8Array(tmpLabel)).slice(1),
		packWithLength(context).slice(1)
	])

	return crypto.expand(algorithm, length, Buffer.from(key), length, hkdfLabel)
}

export async function getHash(msgs: Uint8Array[] | Uint8Array, cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP) {
	if(Array.isArray(msgs) && !(msgs instanceof Uint8Array)) {
		const { hashAlgorithm } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
		return crypto.hash(hashAlgorithm, concatenateUint8Arrays(msgs))
	}

	return msgs
}