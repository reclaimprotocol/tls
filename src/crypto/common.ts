import { OriginatorPublicKey } from '@peculiar/asn1-cms'
import { RSAPublicKey } from '@peculiar/asn1-rsa'
import { AsnParser } from '@peculiar/asn1-schema'
import { PublicKey as RSAPubKey } from 'micro-rsa-dsa-dh/rsa.js'

export function parseRsaPublicKeyFromAsn1(asn1: Uint8Array): RSAPubKey {
	const parsed = AsnParser.parse(asn1, OriginatorPublicKey)
	const rsaPubKey = AsnParser.parse(parsed.publicKey, RSAPublicKey)
	return {
		e: bufToBigint(bufToUint8Array(rsaPubKey.publicExponent)),
		n: bufToBigint(bufToUint8Array(rsaPubKey.modulus)),
	}
}

export function bufToUint8Array(buf: ArrayBuffer | Uint8Array): Uint8Array {
	if(buf instanceof Uint8Array) {
		return buf
	}

	return new Uint8Array(buf)
}

const BITS = 8n

function bufToBigint(buf: Uint8Array): bigint {
	let ret = 0n
	for(const i of buf.values()) {
		const bi = BigInt(i)
		ret = (ret << BITS) + bi
	}

	return ret
}