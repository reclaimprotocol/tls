import { crypto } from '../crypto'
import { AuthenticatedSymmetricCryptoAlgorithm, Key, SymmetricCryptoAlgorithm, TLSProtocolVersion } from '../types'
import { AUTH_TAG_BYTE_LENGTH, CONTENT_TYPE_MAP, SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { areUint8ArraysEqual, concatenateUint8Arrays, generateIV, isSymmetricCipher, padTls, toHexStringWithWhitespace, uint8ArrayToDataView } from './generics'
import { PacketHeaderOptions, packPacketHeader } from './packets'

type WrappedRecordMacGenOptions = {
	macKey?: Key
	recordNumber: number | undefined
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
	version: TLSProtocolVersion
} & ({ recordHeaderOpts: PacketHeaderOptions } | { recordHeader: Uint8Array })

type WrappedRecordCipherOptions = {
	authTag?: Uint8Array
	iv: Uint8Array
	key: Key
} & WrappedRecordMacGenOptions

type EncryptInfo = {
	plaintext: Uint8Array
	contentType?: keyof typeof CONTENT_TYPE_MAP
}

export async function decryptWrappedRecord(
	encryptedData: Uint8Array,
	opts: WrappedRecordCipherOptions
) {
	if(!('recordHeader' in opts)) {
		throw new Error('recordHeader is required for decrypt')
	}

	const {
		authTag,
		key,
		recordNumber,
		cipherSuite,
	} = opts
	const { cipher, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	const iv = recordNumber === undefined
		? opts.iv
		: generateIV(opts.iv, recordNumber)

	return isSymmetricCipher(cipher)
		? doCipherDecrypt(cipher)
		: doAuthCipherDecrypt(cipher)

	async function doCipherDecrypt(cipher: SymmetricCryptoAlgorithm) {
		const iv = encryptedData.slice(0, 16)
		let ciphertext = encryptedData.slice(16)
		if(authTag?.length) {
			ciphertext = concatenateUint8Arrays([ ciphertext, authTag ])
		}

		let plaintextAndMac = await crypto.decrypt(
			cipher,
			{
				key,
				iv,
				data: ciphertext,
			}
		)

		plaintextAndMac = plaintextAndMac.slice(0, -1)

		const mac = plaintextAndMac.slice(-hashLength)
		const plaintext = plaintextAndMac.slice(0, -hashLength)

		const macComputed = await computeMacTls12(plaintext, opts)
		if(!areUint8ArraysEqual(mac, macComputed)) {
			throw new Error(`MAC mismatch: expected ${toHexStringWithWhitespace(macComputed)}, got ${toHexStringWithWhitespace(mac)}`)
		}

		return {
			plaintext,
			contentType: undefined,
			ciphertext,
		}
	}

	async function doAuthCipherDecrypt(cipher: AuthenticatedSymmetricCryptoAlgorithm) {
		const aead = getAead(encryptedData.length, opts)
		// console.log(
		// 	'aead', toHexStringWithWhitespace(aead),
		// 	'cipher', toHexStringWithWhitespace(encryptedData),
		// 	'authTag', toHexStringWithWhitespace(authTag || new Uint8Array(0)),
		// )
		const { plaintext } = await crypto.authenticatedDecrypt(
			cipher,
			{
				key,
				iv,
				data: encryptedData,
				aead,
				authTag,
			}
		)

		if(plaintext.length !== encryptedData.length) {
			throw new Error('Decrypted length does not match encrypted length')
		}

		const totalLength = opts.version === 'TLS1_3'
			// TLS 1.3 has an extra byte for content type
			// exclude final byte (content type)
			? plaintext.length - 1
			: plaintext.length

		return {
			plaintext: plaintext.slice(0, totalLength),
			contentType: plaintext.slice(totalLength, totalLength)[0],
			ciphertext: encryptedData.slice(0, totalLength),
		}
	}
}

export async function encryptWrappedRecord(
	{
		plaintext,
		contentType,
	}: EncryptInfo,
	opts: WrappedRecordCipherOptions
) {
	const {
		key,
		recordNumber,
		cipherSuite,
	} = opts
	const { cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

	let iv = recordNumber === undefined
		? opts.iv
		: generateIV(opts.iv, recordNumber)

	const completePlaintext = contentType
		? concatenateUint8Arrays([
			plaintext,
			new Uint8Array([ CONTENT_TYPE_MAP[contentType] ])
		])
		: plaintext

	return isSymmetricCipher(cipher)
		? doSymmetricEncrypt(cipher)
		: doAuthSymmetricEncrypt(cipher)

	async function doAuthSymmetricEncrypt(cipher: AuthenticatedSymmetricCryptoAlgorithm) {
		const aead = getAead(completePlaintext.length, opts)
		const enc = await crypto.authenticatedEncrypt(
			cipher,
			{
				key,
				iv,
				data: completePlaintext,
				aead,
			}
		)

		// if(!isTls13) {
		// 	enc.ciphertext = concatenateUint8Arrays([
		// 		opts.iv,
		// 		enc.ciphertext,
		// 	])
		// }

		return enc
	}

	async function doSymmetricEncrypt(cipher: SymmetricCryptoAlgorithm) {
		const blockSize = 16
		iv = padBytes(opts.iv, 16).slice(0, 16)

		const mac = await computeMacTls12(completePlaintext, opts)
		const completeData = concatenateUint8Arrays([
			completePlaintext,
			mac,
		])
		// add TLS's special padding :(
		const padded = padTls(completeData, blockSize)
		// console.log(padded.length, 'content ', toHexStringWithWhitespace(padded))
		const result = await crypto.encrypt(
			cipher as SymmetricCryptoAlgorithm,
			{ key, iv, data: padded }
		)

		return {
			ciphertext: concatenateUint8Arrays([
				iv,
				// remove the extra padding webcrypto adds
				result.slice(0, padded.length),
			]),
			authTag: undefined
		}
	}

	function padBytes(arr: Uint8Array, len: number) {
		const returnVal = new Uint8Array(len)
		returnVal.set(arr, len - arr.length)
		return returnVal
	}
}

export function parseWrappedRecord(data: Uint8Array) {
	const encryptedData = data.slice(0, data.length - AUTH_TAG_BYTE_LENGTH)
	const authTag = data.slice(data.length - AUTH_TAG_BYTE_LENGTH)

	return { encryptedData, authTag }
}

function getAead(
	plaintextLength: number,
	opts: WrappedRecordMacGenOptions
) {
	const isTls13 = opts.version === 'TLS1_3'
	let aead: Uint8Array
	if(isTls13) {
		const dataLen = plaintextLength + AUTH_TAG_BYTE_LENGTH
		const recordHeader = 'recordHeaderOpts' in opts
			? packPacketHeader(dataLen, opts.recordHeaderOpts)
			: replaceRecordHeaderLen(opts.recordHeader, dataLen)
		aead = recordHeader
	} else {
		aead = getTls12Header(plaintextLength, opts)
	}

	return aead
}

function getTls12Header(
	plaintextLength: number,
	opts: WrappedRecordMacGenOptions
) {
	const { recordNumber } = opts

	const recordHeader = 'recordHeaderOpts' in opts
		? packPacketHeader(plaintextLength, opts.recordHeaderOpts)
		: replaceRecordHeaderLen(opts.recordHeader, plaintextLength)

	const seqNumberBytes = new Uint8Array(8)
	const seqNumberView = uint8ArrayToDataView(seqNumberBytes)
	seqNumberView.setUint32(4, recordNumber || 0)

	return concatenateUint8Arrays([
		seqNumberBytes,
		recordHeader,
	])
}

async function computeMacTls12(
	plaintext: Uint8Array,
	opts: WrappedRecordMacGenOptions
) {
	const { macKey, cipherSuite } = opts
	if(!macKey) {
		throw new Error('macKey is required for non-AEAD cipher')
	}

	const { hashAlgorithm } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

	const dataToSign = concatenateUint8Arrays([
		getTls12Header(plaintext.length, opts),
		plaintext,
	])

	const mac = await crypto.hmac(hashAlgorithm, macKey, dataToSign)
	return mac
}

function replaceRecordHeaderLen(header: Uint8Array, newLength: number) {
	const newRecordHeader = new Uint8Array(header)
	const dataView = uint8ArrayToDataView(newRecordHeader)
	dataView.setUint16(3, newLength)
	return newRecordHeader
}