import { TLSSessionTicket } from '../types'
import { getHash, hkdfExtractAndExpandLabel } from '../utils/decryption-utils'
import { SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { expectReadWithLength } from './packets'
import { uint8ArrayToDataView } from './generics'
import { crypto } from '../crypto'

type GetResumableSessionTicketOptions = {
	masterKey: Uint8Array
	/** hello msgs without record header */
	hellos: Uint8Array[] | Uint8Array
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export function parseSessionTicket(data: Uint8Array) {
	const lifetimeS = read(4).getUint32(0)
	const ticketAgeAddMs = read(4).getUint32(0)

	const nonce = readWLength(1)
	const ticket = readWLength(2)

	const extensions = readWLength(2)

	const sessionTicket: TLSSessionTicket = {
		ticket,
		lifetimeS,
		ticketAgeAddMs,
		nonce,
		expiresAt: new Date(Date.now() + lifetimeS * 1000),
		extensions
	}

	return sessionTicket

	function read(bytes: number) {
		const result = data.slice(0, bytes)
		data = data.slice(bytes)
		return uint8ArrayToDataView(result)
	}

	function readWLength(bytesLength = 2) {
		const content = expectReadWithLength(data, bytesLength)
		data = data.slice(content.length + bytesLength)

		return content
	}
}

export async function getPskFromTicket(
	ticket: TLSSessionTicket,
	{
		masterKey,
		hellos,
		cipherSuite
	}: GetResumableSessionTicketOptions
) {
	const { hashAlgorithm, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const handshakeHash = await getHash(hellos, cipherSuite)

	const resumeMasterSecret = await hkdfExtractAndExpandLabel(hashAlgorithm, masterKey, 'res master', handshakeHash, hashLength)
	const psk = await hkdfExtractAndExpandLabel(hashAlgorithm, resumeMasterSecret, 'resumption', ticket.nonce, hashLength)

	const emptyHash = await crypto.hash(hashAlgorithm, new Uint8Array())
	const earlySecret = await crypto.extract(hashAlgorithm, hashLength, psk, '')

	const binderKey = await hkdfExtractAndExpandLabel(hashAlgorithm, earlySecret, 'res binder', emptyHash, hashLength)
	// const clientEarlyTrafficSecret = hkdfExtractAndExpandLabel(hashAlgorithm, earlySecret, 'c e traffic', new Uint8Array(), hashLength)
	const finishKey = await hkdfExtractAndExpandLabel(hashAlgorithm, binderKey, 'finished', new Uint8Array(), hashLength)

	const ticketAge = Math.floor(ticket.lifetimeS / 1000 + ticket.ticketAgeAddMs)

	return {
		identity: ticket.ticket,
		ticketAge,
		finishKey: await crypto.importKey(hashAlgorithm, finishKey),
		resumeMasterSecret,
		earlySecret,
		cipherSuite,
	}
}