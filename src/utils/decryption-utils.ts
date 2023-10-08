import { crypto } from '../crypto'
import { CipherSuite, HashAlgorithm } from '../types'
import { SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { concatenateUint8Arrays, isSymmetricCipher, strToUint8Array, uint8ArrayToDataView } from './generics'
import { packWithLength } from './packets'

type DeriveTrafficKeysOptions = {
	masterSecret: Uint8Array
	/** used to derive keys when resuming session */
	earlySecret?: Uint8Array

	cipherSuite: CipherSuite
	/** list of handshake message to hash; or the hash itself */
	hellos: Uint8Array[] | Uint8Array
	/** type of secret; handshake or provider-data */
	secretType: 'hs' | 'ap'
}

type DeriveTrafficKeysOptionsTls12 = {
	preMasterSecret: Uint8Array
	clientRandom: Uint8Array
	serverRandom: Uint8Array
	cipherSuite: CipherSuite
}

export type SharedKeyData = Awaited<ReturnType<typeof computeSharedKeys>>
	| Awaited<ReturnType<typeof computeSharedKeysTls12>>

const TLS1_2_BASE_SEED = strToUint8Array('master secret')
const TLS1_2_KEY_EXPANSION_SEED = strToUint8Array('key expansion')

export async function computeSharedKeysTls12(opts: DeriveTrafficKeysOptionsTls12) {
	const {
		clientRandom,
		serverRandom,
		cipherSuite,
	} = opts
	const masterSecret = await generateMasterSecret(opts)
	// all key derivation in TLS 1.2 uses SHA-256
	const hashAlgorithm = getPrfHashAlgorithm(cipherSuite)

	const {
		keyLength,
		cipher,
		hashLength,
		hashAlgorithm: cipherHashAlg,
		ivLength
	} = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const masterKey = await crypto
		.importKey(hashAlgorithm, masterSecret)
	const seed = concatenateUint8Arrays([
		TLS1_2_KEY_EXPANSION_SEED,
		serverRandom,
		clientRandom,
	])

	const expandedSecretArr: Uint8Array[] = []
	let lastSeed = seed
	for(let i = 0; i < 4; i++) {
		lastSeed = await crypto.hmac(
			hashAlgorithm,
			masterKey,
			lastSeed
		)
		const expandedSecret = await crypto.hmac(
			hashAlgorithm,
			masterKey,
			concatenateUint8Arrays([
				lastSeed,
				seed
			])
		)

		expandedSecretArr.push(expandedSecret)
	}

	let expandedSecret = concatenateUint8Arrays(expandedSecretArr)

	const needsMac = isSymmetricCipher(cipher)
	const clientMacKey = needsMac ? await crypto.importKey(
		cipherHashAlg,
		readExpandedSecret(hashLength),
	) : undefined
	const serverMacKey = needsMac ? await crypto.importKey(
		cipherHashAlg,
		readExpandedSecret(hashLength)
	) : undefined

	const clientEncKey = await crypto.importKey(
		cipher,
		readExpandedSecret(keyLength)
	)

	const serverEncKey = await crypto.importKey(
		cipher,
		readExpandedSecret(keyLength)
	)

	const clientIv = readExpandedSecret(ivLength)
	const serverIv = readExpandedSecret(ivLength)

	return {
		type: 'TLS1_2' as const,
		masterSecret,
		clientMacKey,
		serverMacKey,
		clientEncKey,
		serverEncKey,
		clientIv,
		serverIv,
		serverSecret: masterSecret,
		clientSecret: masterSecret,
	}

	function readExpandedSecret(len: number) {
		const returnVal = expandedSecret
			.slice(0, len)
		expandedSecret = expandedSecret
			.slice(len)
		return returnVal
	}
}

async function generateMasterSecret({
	preMasterSecret,
	clientRandom,
	serverRandom,
	cipherSuite
}: DeriveTrafficKeysOptionsTls12) {
	// all key derivation in TLS 1.2 uses SHA-256
	const hashAlgorithm = getPrfHashAlgorithm(cipherSuite)
	const preMasterKey = await crypto
		.importKey(hashAlgorithm, preMasterSecret)
	const seed = concatenateUint8Arrays([
		TLS1_2_BASE_SEED,
		clientRandom,
		serverRandom
	])

	const a1 = await crypto.hmac(
		hashAlgorithm,
		preMasterKey,
		seed
	)
	const a2 = await crypto.hmac(
		hashAlgorithm,
		preMasterKey,
		a1
	)
	const p1 = await crypto.hmac(
		hashAlgorithm,
		preMasterKey,
		concatenateUint8Arrays([
			a1,
			seed
		])
	)
	const p2 = await crypto.hmac(
		hashAlgorithm,
		preMasterKey,
		concatenateUint8Arrays([
			a2,
			seed
		])
	)
	return concatenateUint8Arrays([ p1, p2 ])
		.slice(0, 48)
}

export function computeUpdatedTrafficMasterSecret(
	masterSecret: Uint8Array,
	cipherSuite: CipherSuite
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

		handshakeTrafficSecret = await crypto.extract(hashAlgorithm, hashLength, masterKey, derivedSecret)
	} else {
		const derivedSecret = await hkdfExtractAndExpandLabel(hashAlgorithm, masterKey, 'derived', emptyHash, hashLength)
		handshakeTrafficSecret = await crypto.extract(hashAlgorithm, hashLength, zeros, derivedSecret)
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
		type: 'TLS1_3' as const,
		masterSecret,
		clientSecret,
		serverSecret,
		clientEncKey,
		serverEncKey,
		clientIv,
		serverIv,
	}
}

export async function deriveTrafficKeysForSide(masterSecret: Uint8Array, cipherSuite: CipherSuite) {
	const { hashAlgorithm, keyLength, cipher, ivLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const encKey = await hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'key', new Uint8Array(), keyLength)
	const iv = await hkdfExtractAndExpandLabel(hashAlgorithm, masterSecret, 'iv', new Uint8Array(0), ivLength)

	return {
		masterSecret,
		encKey: await crypto.importKey(cipher, encKey),
		iv
	}
}

export async function hkdfExtractAndExpandLabel(algorithm: HashAlgorithm, secret: Uint8Array, label: string, context: Uint8Array, length: number) {
	const tmpLabel = `tls13 ${label}`
	const lengthBuffer = new Uint8Array(2)
	const lengthBufferView = uint8ArrayToDataView(lengthBuffer)
	lengthBufferView.setUint16(0, length)
	const hkdfLabel = concatenateUint8Arrays([
		lengthBuffer,
		packWithLength(strToUint8Array(tmpLabel)).slice(1),
		packWithLength(context).slice(1)
	])

	const key = await crypto.importKey(algorithm, secret)
	return crypto.expand(algorithm, length, key, length, hkdfLabel)
}

export async function getHash(msgs: Uint8Array[] | Uint8Array, cipherSuite: CipherSuite) {
	if(Array.isArray(msgs) && !(msgs instanceof Uint8Array)) {
		const { hashAlgorithm } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
		return crypto.hash(hashAlgorithm, concatenateUint8Arrays(msgs))
	}

	return msgs
}

/**
 * Get the PRF algorithm for the given cipher suite
 * Relevant for TLS 1.2
 */
export function getPrfHashAlgorithm(cipherSuite: CipherSuite) {
	const opts = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	// all key derivation in TLS 1.2 uses min SHA-256
	return ('prfHashAlgorithm' in opts)
		? opts.prfHashAlgorithm
		: opts.hashAlgorithm
}