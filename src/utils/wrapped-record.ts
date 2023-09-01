import { concatenateUint8Arrays, xor } from './generics'
import { AUTH_TAG_BYTE_LENGTH, CONTENT_TYPE_MAP, SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { crypto } from '../crypto'
import { Key } from '../types'

type WrappedRecordCipherOptions = {
	authTag?: Uint8Array
	iv: Uint8Array
	key: Key
	recordHeader: Uint8Array
	recordNumber: number | undefined
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
}

export async function decryptWrappedRecord(
	encryptedData: Uint8Array,
	{
		authTag,
		key,
		iv,
		recordHeader,
		recordNumber,
		cipherSuite,
	}: WrappedRecordCipherOptions
) {
	const { cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	iv = recordNumber === undefined
		? iv
		: generateIV(iv, recordNumber)
	const { plaintext } = await crypto.authenticatedDecrypt(
		cipher,
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

export async function encryptWrappedRecord(
	{ plaintext, contentType }: { plaintext: Uint8Array, contentType: keyof typeof CONTENT_TYPE_MAP },
	{
		key,
		iv,
		recordHeader,
		recordNumber,
		cipherSuite,
	}: WrappedRecordCipherOptions
) {
	const { cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const completePlaintext = concatenateUint8Arrays([
		plaintext,
		new Uint8Array([ CONTENT_TYPE_MAP[contentType] ])
	])
	iv = recordNumber === undefined ? iv : generateIV(iv, recordNumber)
	return crypto.authenticatedEncrypt(
		cipher,
		{
			key,
			iv,
			data: completePlaintext,
			aead: recordHeader,
		}
	)
}

export function parseWrappedRecord(data: Uint8Array) {
	const encryptedData = data.slice(0, data.length - AUTH_TAG_BYTE_LENGTH)
	const authTag = data.slice(data.length - AUTH_TAG_BYTE_LENGTH)

	return { encryptedData, authTag }
}

export function generateIV(iv: Uint8Array, recordNumber: number) {
	// make the recordNumber a buffer, so we can XOR with the main IV
	// to generate the specific IV to decrypt this packet
	const recordBuffer = new Uint8Array(iv.length)
	const recordBufferView = new DataView(recordBuffer.buffer)
	recordBufferView.setUint32(iv.length - 4, recordNumber)
	return xor(iv, recordBuffer)
}