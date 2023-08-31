import { createCipheriv, createDecipheriv, createHash } from 'crypto'
import { expand, extract } from 'futoin-hkdf'
import { AUTH_TAG_BYTE_LENGTH, SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { packWithLength } from './packets'
import { TLSCrypto } from '../types'
import { concatenateUint8Arrays, strToUint8Array, uint8ArrayToDataView } from './generics'

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

export const NODEJS_TLS_CRYPTO: TLSCrypto = {
	encrypt(cipherSuite, { key, iv, data, aead }) {
		const { cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

		const encryptr = createCipheriv(
			cipher,
			key,
			iv,
			// @ts-expect-error
			{ authTagLength: AUTH_TAG_BYTE_LENGTH }
		)
		encryptr.setAutoPadding(false)
		encryptr.setAAD(aead, { plaintextLength: data.length })

		const ciphertext = concatenateUint8Arrays([
			encryptr.update(data),
			encryptr.final()
		])
		const authTag = encryptr.getAuthTag()

		return { ciphertext, authTag }
	},
	decrypt(cipherSuite, { key, iv, data, aead, authTag }) {
		const { cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
		const decipher = createDecipheriv(
			cipher,
			key,
			iv,
			// @ts-expect-error
			{ authTagLength: AUTH_TAG_BYTE_LENGTH }
		)
		decipher.setAutoPadding(false)
		if(authTag) {
			decipher.setAuthTag(authTag)
		}

		decipher.setAAD(aead, { plaintextLength: data.length })

		const plaintext = concatenateUint8Arrays([
			decipher.update(data),
			// essentially, we skip validating the data
			// if we don't have an auth tag
			// this is insecure generally, and auth tag validation
			// should happen at some point
			authTag ? decipher.final() : new Uint8Array(),
		])

		return { plaintext }
	}
}

export type SharedKeyData = ReturnType<typeof computeSharedKeys>

export function computeUpdatedTrafficMasterSecret(
	masterSecret: Uint8Array,
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	return hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'traffic upd', new Uint8Array(), hashLength)
}

export function computeSharedKeys({
	hellos,
	masterSecret: masterKey,
	cipherSuite,
	secretType,
	earlySecret
}: DeriveTrafficKeysOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

	const emptyHash = createHash(hashAlgorithm).update('').digest()
	const zeros = new Uint8Array(hashLength)
	let handshakeTrafficSecret: Uint8Array
	if(secretType === 'hs') {
		// some hashes
		earlySecret = earlySecret || extract(hashAlgorithm, hashLength, Buffer.from(zeros), '')
		const derivedSecret = hkdfExtractAndExpandLabel(hashAlgorithm, earlySecret, 'derived', emptyHash, hashLength)

		handshakeTrafficSecret = extract(hashAlgorithm, hashLength, Buffer.from(masterKey), derivedSecret)
	} else {
		const derivedSecret = hkdfExtractAndExpandLabel(hashAlgorithm, masterKey, 'derived', emptyHash, hashLength)
		handshakeTrafficSecret = extract(hashAlgorithm, hashLength, Buffer.from(zeros), derivedSecret)
	}

	return deriveTrafficKeys({
		hellos,
		cipherSuite,
		masterSecret: handshakeTrafficSecret,
		secretType
	})
}

export function deriveTrafficKeys({
	masterSecret,
	cipherSuite,
	hellos,
	secretType,
}: DeriveTrafficKeysOptions) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

	const handshakeHash = getHash(hellos, cipherSuite)

	const clientSecret = hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, `c ${secretType} traffic`, handshakeHash, hashLength)
	const serverSecret = hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, `s ${secretType} traffic`, handshakeHash, hashLength)
	const { encKey: clientEncKey, iv: clientIv } = deriveTrafficKeysForSide(clientSecret, cipherSuite)
	const { encKey: serverEncKey, iv: serverIv } = deriveTrafficKeysForSide(serverSecret, cipherSuite)

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

export function deriveTrafficKeysForSide(masterSecret: Uint8Array, cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP) {
	const { hashAlgorithm, keyLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const ivLen = 12

	const encKey = hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'key', new Uint8Array(), keyLength)
	const iv = hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'iv', new Uint8Array(0), ivLen)

	return { masterSecret, encKey, iv }
}

export function hkdfExtractAndExpandLabel(algorithm: string, key: Uint8Array, label: string, context: Uint8Array, length: number) {
	const tmpLabel = `tls13 ${label}`
	const lengthBuffer = new Uint8Array(2)
	const lengthBufferView = uint8ArrayToDataView(lengthBuffer)
	lengthBufferView.setUint16(0, length)
	const hkdfLabel = concatenateUint8Arrays([
		lengthBuffer,
		packWithLength(strToUint8Array(tmpLabel)).slice(1),
		packWithLength(context).slice(1)
	])

	return expand(algorithm, length, Buffer.from(key), length, Buffer.from(hkdfLabel))
}

export function getHash(msgs: Uint8Array[] | Uint8Array, cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP) {
	if(Array.isArray(msgs) && !(msgs instanceof Uint8Array)) {
		const { hashAlgorithm } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
		const hasher = createHash(hashAlgorithm)
		for(const msg of msgs) {
			hasher.update(msg)
		}

		return hasher.digest()
	}

	return msgs
}