import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'crypto'
import * as curveJs from 'curve25519-js'

// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
	48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
])

const PRIVATE_KEY_DER_PREFIX = Buffer.from([
	48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
])

export function calculateSharedKey(privKey: Buffer, pubKey: Buffer) {
	if(typeof createPrivateKey === 'function' && typeof createPublicKey === 'function') {
		const nodePrivateKey = createPrivateKey({
			key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
			format: 'der',
			type: 'pkcs8'
		})
		const nodePublicKey = createPublicKey({
			key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
			format: 'der',
			type: 'spki'
		})

		return diffieHellman({
			privateKey: nodePrivateKey,
			publicKey: nodePublicKey,
		})
	}

	return Buffer.from(curveJs.sharedKey(privKey, pubKey))
}

export function generateX25519KeyPair() {
	if(typeof generateKeyPairSync === 'function') {
		const { publicKey: publicDerBytes, privateKey: privateDerBytes } = generateKeyPairSync(
			'x25519',
			{
				publicKeyEncoding: { format: 'der', type: 'spki' },
				privateKeyEncoding: { format: 'der', type: 'pkcs8' }
			}
		)

		const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32)
		const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32)

		return {
			pubKey,
			privKey
		}
	}

	const keys = curveJs.generateKeyPair(randomBytes(32))
	return {
		pubKey: Buffer.from(keys.public),
		privKey: Buffer.from(keys.private)
	}
}