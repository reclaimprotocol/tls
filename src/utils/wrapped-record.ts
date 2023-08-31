import { TLSCrypto } from '../types'
import { xor } from './generics'
import { AUTH_TAG_BYTE_LENGTH, CONTENT_TYPE_MAP, SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { NODEJS_TLS_CRYPTO } from './decryption-utils'

type WrappedRecordCipherOptions = {
	authTag?: Uint8Array
	iv: Uint8Array
	key: Uint8Array
	recordHeader: Uint8Array
	recordNumber: number | undefined
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
	crypto?: TLSCrypto
}

export function decryptWrappedRecord(
	encryptedData: Uint8Array,
	{
		authTag,
		key,
		iv,
		recordHeader,
		recordNumber,
		cipherSuite,
		crypto,
	}: WrappedRecordCipherOptions
) {
	crypto ||= NODEJS_TLS_CRYPTO
	iv = recordNumber === undefined
		? iv
		: generateIV(iv, recordNumber)
	const { plaintext } = crypto.decrypt(
		cipherSuite,
		{
			key,
			iv,
			data: encryptedData,
			aead: recordHeader,
			authTag,
		}
	)

	if(plaintext.length !== encryptedData.length) {
		throw new Error('Decrypted length does not match encrypted length')
	}

	return {
		plaintext: plaintext.slice(0, -1),
		contentType: plaintext[plaintext.length - 1],
	}
}

export function encryptWrappedRecord(
	{ plaintext, contentType }: { plaintext: Buffer, contentType: keyof typeof CONTENT_TYPE_MAP },
	{
		key,
		iv,
		recordHeader,
		recordNumber,
		cipherSuite,
		crypto,
	}: WrappedRecordCipherOptions
) {
	crypto ||= NODEJS_TLS_CRYPTO
	const completePlaintext = Buffer.concat([
		plaintext,
		Buffer.from([ CONTENT_TYPE_MAP[contentType] ])
	])
	iv = recordNumber === undefined ? iv : generateIV(iv, recordNumber)
	return crypto.encrypt(
		cipherSuite,
		{
			key,
			iv,
			data: completePlaintext,
			aead: recordHeader,
		}
	)
}

export function parseWrappedRecord(data: Buffer) {
	const encryptedData = data.slice(0, data.length - AUTH_TAG_BYTE_LENGTH)
	const authTag = data.slice(data.length - AUTH_TAG_BYTE_LENGTH)

	return { encryptedData, authTag }
}

export function generateIV(iv: Uint8Array, recordNumber: number) {
	// make the recordNumber a buffer, so we can XOR with the main IV
	// to generate the specific IV to decrypt this packet
	const recordBuffer = Buffer.alloc(iv.length)
	recordBuffer.writeUInt32BE(recordNumber, iv.length - 4)

	return xor(iv, recordBuffer)
}