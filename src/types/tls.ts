import type { Logger } from 'pino'
import type { SUPPORTED_CIPHER_SUITE_MAP } from '../utils/constants'
import type { X509Certificate } from './x509'

type TLSCryptoCryptOptions = {
	key: Uint8Array
	iv: Uint8Array
	data: Uint8Array
	aead: Uint8Array
	authTag?: Uint8Array
}

export type TLSCrypto = {
	encrypt(
		cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP,
		opts: TLSCryptoCryptOptions
	): { ciphertext: Buffer, authTag: Buffer }
	decrypt(
		cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP,
		opts: TLSCryptoCryptOptions
	): { plaintext: Buffer }
}

export type TLSPacket = {
	header: Buffer
	content: Buffer
	authTag?: Buffer
}

export type TLSConnectionOptions = {
	/**
	 * if true, an out of band PSK (pre-shared key)
	 * will be generated before connecting via the verifier node
	 * */
	generateOutOfBandSession?: boolean
	/**
	 * if false, the server certificate will not be verified
	 * Use with caution; without server certificate verification
	 * it is super easy to MITM the connection & reveal any secrets
	 */
	verifyServerCertificate?: boolean
	/**
	 * if provided, the server certificate will be verified against these root CAs
	 */
	rootCAs?: X509Certificate[]

	/** crypto functions */
	crypto?: TLSCrypto

	/** the cipher suites the client will claim it supports */
	cipherSuites?: (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]
}

export type TLSClientOptions = TLSConnectionOptions & {
	host: string
	/**
	 * should it expect the last bytes of a wrapped-record
	 * to have an auth tag
	 * @default true
	 * */
	expectAuthTagInWrappedRecord?: boolean

	logger?: Logger

	write(packet: TLSPacket): Promise<void>
}

export type TLSPresharedKey = {
	identity: Buffer
	ticketAge: number
	finishKey: Buffer
	earlySecret: Buffer
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export type TLSSessionTicket = {
	expiresAt: Date
	lifetimeS: number
	ticketAgeAddMs: number
	nonce: Buffer
	ticket: Buffer
	extensions: Buffer
}

export type TLSHandshakeOptions = {
	random?: Buffer
	psk?: TLSPresharedKey
}

export type TLSEventMap = {
	handshake: undefined
	'recv-certificates': { certificates: X509Certificate[] }
	data: {
		plaintext: Buffer
		ciphertext: Buffer
		authTag: Buffer
	}
	end: { error?: Error }
	'session-ticket': TLSSessionTicket
}

export interface TLSEventEmitter {
	on<T extends keyof TLSEventMap>(event: T, listener: (arg: TLSEventMap[T]) => void): void
	once<T extends keyof TLSEventMap>(event: T, listener: (arg: TLSEventMap[T]) => void): void
    off<T extends keyof TLSEventMap>(event: T, listener: (arg: TLSEventMap[T]) => void): void
    removeAllListeners<T extends keyof TLSEventMap>(event: T): void
	emit<T extends keyof TLSEventMap>(event: T, arg: TLSEventMap[T]): boolean
}

export type ProcessPacket = (type: number, packet: TLSPacket) => void

export type PacketProcessor = {
	onData(data: Buffer, onChunk: ProcessPacket): void
}