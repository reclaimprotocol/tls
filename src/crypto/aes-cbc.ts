/**
 * Temporary solution for AES-CBC decryption
 */
import { createDecipheriv } from 'crypto'
import { concatenateUint8Arrays } from '../utils/generics.ts'

export function decryptAesCbc(key: Uint8Array, iv: Uint8Array, buf: Uint8Array) {
	const cipherName = key.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc'
	const cipher = createDecipheriv(cipherName, key, iv)
	cipher.setAutoPadding(false)

	return concatenateUint8Arrays([
		cipher.update(buf),
		cipher.final()
	])
}