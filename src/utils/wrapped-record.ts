import { crypto } from '../crypto'
import { AuthenticatedSymmetricCryptoAlgorithm, Key, SymmetricCryptoAlgorithm, TLSProtocolVersion } from '../types'
import { AUTH_TAG_BYTE_LENGTH, SUPPORTED_CIPHER_SUITE_MAP } from './constants'
import { areUint8ArraysEqual, concatenateUint8Arrays, generateIV, isSymmetricCipher, padTls, toHexStringWithWhitespace, uint8ArrayToDataView, unpadTls } from './generics'
import { PacketHeaderOptions, packPacketHeader } from './packets'

type WrappedRecordMacGenOptions = {
	macKey?: Key
	recordNumber: number | undefined
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP
	version: TLSProtocolVersion
} & ({ recordHeaderOpts: PacketHeaderOptions } | { recordHeader: Uint8Array })

type WrappedRecordCipherOptions = {
	iv: Uint8Array
	key: Key
} & WrappedRecordMacGenOptions

const AUTH_CIPHER_LENGTH = 12

export async function decryptWrappedRecord(
	encryptedData: Uint8Array,
	opts: WrappedRecordCipherOptions
) {
	if(!('recordHeader' in opts)) {
		throw new Error('recordHeader is required for decrypt')
	}

	const {
		key,
		recordNumber,
		cipherSuite,
	} = opts
	const { cipher, hashLength } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	return isSymmetricCipher(cipher)
		? doCipherDecrypt(cipher)
		: doAuthCipherDecrypt(cipher)

	async function doCipherDecrypt(cipher: SymmetricCryptoAlgorithm) {
		const iv = encryptedData.slice(0, 16)
		const ciphertext = encryptedData.slice(16)

		let plaintextAndMac = await crypto.decrypt(
			cipher,
			{
				key,
				iv,
				data: ciphertext,
			}
		)

		plaintextAndMac = unpadTls(plaintextAndMac)
		plaintextAndMac = plaintextAndMac.slice(0, -1)

		const mac = plaintextAndMac.slice(-hashLength)
		const plaintext = plaintextAndMac.slice(0, -hashLength)

		const macComputed = await computeMacTls12(plaintext, opts)
		if(!areUint8ArraysEqual(mac, macComputed)) {
			throw new Error(`MAC mismatch: expected ${toHexStringWithWhitespace(macComputed)}, got ${toHexStringWithWhitespace(mac)}`)
		}

		return { plaintext, iv }
	}

	async function doAuthCipherDecrypt(cipher: AuthenticatedSymmetricCryptoAlgorithm) {
		let iv = opts.iv
		const recordIvLength = AUTH_CIPHER_LENGTH - iv.length
		if(recordIvLength) {
			// const recordIv = new Uint8Array(recordIvLength)
			// const seqNumberView = uint8ArrayToDataView(recordIv)
			// seqNumberView.setUint32(recordIvLength - 4, recordNumber)
			const recordIv = encryptedData.slice(0, recordIvLength)
			encryptedData = encryptedData.slice(recordIvLength)

			iv = concatenateUint8Arrays([
				iv,
				recordIv
			])
		} else if(
			// use IV generation alg for TLS 1.3
			// and ChaCha20-Poly1305
			(
				opts.version === 'TLS1_3'
				|| cipher === 'CHACHA20-POLY1305'
			) && typeof recordNumber !== 'undefined'
		) {
			iv = generateIV(iv, recordNumber)
		}

		const authTag = encryptedData.slice(-AUTH_TAG_BYTE_LENGTH)
		encryptedData = encryptedData.slice(0, -AUTH_TAG_BYTE_LENGTH)

		const aead = getAead(encryptedData.length, opts)
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

		return { plaintext, iv }
	}
}

export async function encryptWrappedRecord(
	plaintext: Uint8Array,
	opts: WrappedRecordCipherOptions
) {
	const {
		key,
		recordNumber,
		cipherSuite,
	} = opts
	const { cipher } = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]
	let iv = opts.iv

	return isSymmetricCipher(cipher)
		? doSymmetricEncrypt(cipher)
		: doAuthSymmetricEncrypt(cipher)

	async function doAuthSymmetricEncrypt(cipher: AuthenticatedSymmetricCryptoAlgorithm) {
		const aead = getAead(plaintext.length, opts)

		// record IV is the record number as a 64-bit big-endian integer
		const recordIvLength = AUTH_CIPHER_LENGTH - iv.length
		let recordIv: Uint8Array | undefined
		let completeIv = iv
		if(recordIvLength && typeof recordNumber !== 'undefined') {
			recordIv = new Uint8Array(recordIvLength)
			const seqNumberView = uint8ArrayToDataView(recordIv)
			seqNumberView.setUint32(recordIvLength - 4, recordNumber)

			completeIv = concatenateUint8Arrays([
				iv,
				recordIv
			])
		} else if(
			// use IV generation alg for TLS 1.3
			// and ChaCha20-Poly1305
			(opts.version === 'TLS1_3'
				|| cipher === 'CHACHA20-POLY1305')
			&& typeof recordNumber !== 'undefined'
		) {
			completeIv = generateIV(completeIv, recordNumber)
		}

		const enc = await crypto.authenticatedEncrypt(
			cipher,
			{
				key,
				iv: completeIv,
				data: plaintext,
				aead,
			}
		)

		if(recordIv) {
			enc.ciphertext = concatenateUint8Arrays([
				recordIv,
				enc.ciphertext,
			])
		}

		return {
			ciphertext: concatenateUint8Arrays([
				enc.ciphertext,
				enc.authTag,
			]),
			iv: completeIv
		}
	}

	async function doSymmetricEncrypt(cipher: SymmetricCryptoAlgorithm) {
		const blockSize = 16
		iv = padBytes(opts.iv, 16).slice(0, 16)

		const mac = await computeMacTls12(plaintext, opts)
		const completeData = concatenateUint8Arrays([
			plaintext,
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
				result
			]),
			iv,
		}
	}

	function padBytes(arr: Uint8Array, len: number) {
		const returnVal = new Uint8Array(len)
		returnVal.set(arr, len - arr.length)
		return returnVal
	}
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