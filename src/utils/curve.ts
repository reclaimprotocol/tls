import { ec as EC } from 'elliptic'
import { SUPPORTED_KEY_TYPES } from './constants'
import { CurveImplementation } from '../types'
import { calculateSharedKey, generateX25519KeyPair } from './x25519'

type SupportedCurve = typeof SUPPORTED_KEY_TYPES[number]

export const CURVES: { [C in SupportedCurve]: CurveImplementation } = {
	X25519: {
		generateKeyPair: generateX25519KeyPair,
		calculateSharedKey: calculateSharedKey
	},
	SECP384R1: getEllipticCurveImplementation(new EC('p384'))
}

function getEllipticCurveImplementation(curve: EC) {
	return {
		generateKeyPair() {
			const keyPair = curve.genKeyPair()
			return {
				pubKey: Buffer.from(keyPair.getPublic('array')),
				privKey: Buffer.from(keyPair.getPrivate().toArray())
			}
		},
		calculateSharedKey(privKey, pubKey) {
			const keyPair = curve.keyFromPrivate(privKey)
			const pubKeyPoint = curve.keyFromPublic(pubKey)
			const sharedKey = keyPair.derive(pubKeyPoint.getPublic())

			return Buffer.from(sharedKey.toArray())
		}
	}
}