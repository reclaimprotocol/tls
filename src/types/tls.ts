import type { CONTENT_TYPE_MAP, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_NAMED_CURVE_MAP, TLS_PROTOCOL_VERSION_MAP } from '../utils/constants'
import type { Key } from './crypto'
import { Logger } from './logger'
import type { X509Certificate } from './x509'

export type TLSProtocolVersion = keyof typeof TLS_PROTOCOL_VERSION_MAP

export type CipherSuite = keyof typeof SUPPORTED_CIPHER_SUITE_MAP

export type TLSPacket = {
	header: Uint8Array
	content: Uint8Array
}

export type TLSPacketContext = {
	type: 'plaintext'
} | {
	type: 'ciphertext'
	encKey: Key
	/** IV for the session. Computed at handshake */
	fixedIv: Uint8Array
	/** Actual IV used in the cipher process */
	iv: Uint8Array
	macKey?: Key
	recordNumber: number
	contentType?: keyof typeof CONTENT_TYPE_MAP
	/**
	 * Ciphertext of the record
	 * includes the content type,
	 * and authTag/MAC
	 */
	ciphertext: Uint8Array
	plaintext: Uint8Array
}

export type TLSProcessContext = {
	version: TLSProtocolVersion
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
	/** the cipher suites the client will claim it supports */
	cipherSuites?: (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[]
	/** the named curves the client will claim it supports */
	namedCurves?: (keyof typeof SUPPORTED_NAMED_CURVE_MAP)[]
	/** Only allow connecting via these TLS versions */
	supportedProtocolVersions?: TLSProtocolVersion[]
}

export type TLSClientOptions = TLSConnectionOptions & TLSEventHandlers & {
	/** the hostname of the server to connect to */
	host: string
	/**
	 * should it expect the last bytes of a wrapped-record
	 * to have an auth tag
	 * @default true
	 * */
	expectAuthTagInWrappedRecord?: boolean

	logger?: Logger

	write(packet: TLSPacket, ctx: TLSPacketContext): Promise<void>
}

export type TLSPresharedKey = {
	identity: Uint8Array
	ticketAge: number
	finishKey: Key
	earlySecret: Uint8Array
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export type TLSSessionTicket = {
	expiresAt: Date
	lifetimeS: number
	ticketAgeAddMs: number
	nonce: Uint8Array
	ticket: Uint8Array
	extensions: Uint8Array
}

export type TLSHandshakeOptions = {
	random?: Uint8Array
	psk?: TLSPresharedKey
}

export type TLSEventHandlers = {
	onHandshake?(): void
	onRecvCertificates?(obj: { certificates: X509Certificate[] }): void
	/** Called before any packet is processed */
	onRead?(packet: TLSPacket, ctx: TLSPacketContext): void
	onApplicationData?(plaintext: Uint8Array): void
	onTlsEnd?(error?: Error): void
	onSessionTicket?(ticket: TLSSessionTicket): void
}

export type ProcessPacket = (type: number, packet: TLSPacket) => void

export type PacketProcessor = {
	onData(data: Uint8Array, onChunk: ProcessPacket): void
}