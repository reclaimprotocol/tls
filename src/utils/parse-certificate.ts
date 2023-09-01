import type { CertificatePublicKey, X509Certificate } from '../types'
import { getHash } from './decryption-utils'
import { loadX509FromDer } from '../utils/x509'
import { SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_SIGNATURE_ALGS, SUPPORTED_SIGNATURE_ALGS_MAP } from './constants'
import { expectReadWithLength } from './packets'
import { ROOT_CAS } from './root-ca'
import { areUint8ArraysEqual, concatenateUint8Arrays, strToUint8Array } from './generics'

type VerifySignatureOptions = {
	signature: Uint8Array
	algorithm: keyof typeof SUPPORTED_SIGNATURE_ALGS_MAP
	publicKey: CertificatePublicKey
	cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP

	hellos: Uint8Array[] | Uint8Array
}

const CERT_VERIFY_TXT = strToUint8Array('TLS 1.3, server CertificateVerify')

export function parseCertificates(data: Uint8Array) {
	// context, kina irrelevant
	const ctx = read(1).at(0)!
	// the data itself
	data = readWLength(3)

	const certificates: X509Certificate[] = []
	while(data.length > 0) {
		// the certificate data
		const cert = readWLength(3)
		const certObj = loadX509FromDer(cert)

		certificates.push(certObj)
		// extensions
		readWLength(2)
	}

	return {
		certificates,
		ctx
	}

	function read(bytes: number) {
		const result = data.slice(0, bytes)
		data = data.slice(bytes)
		return result
	}

	function readWLength(bytesLength = 2) {
		const content = expectReadWithLength(data, bytesLength)
		data = data.slice(content.length + bytesLength)

		return content
	}
}

export function parseServerCertificateVerify(data: Uint8Array) {
	// data = readWLength(2)
	const algorithmBytes = read(2)
	const algorithm = SUPPORTED_SIGNATURE_ALGS.find(
		alg => (
			areUint8ArraysEqual(
				SUPPORTED_SIGNATURE_ALGS_MAP[alg]
					.identifier,
				algorithmBytes
			)
		)
	)

	if(!algorithm) {
		throw new Error(`Unsupported signature algorithm '${algorithmBytes}'`)
	}

	const signature = readWLength(2)

	return { algorithm, signature }

	function read(bytes: number) {
		const result = data.slice(0, bytes)
		data = data.slice(bytes)
		return result
	}

	function readWLength(bytesLength = 2) {
		const content = expectReadWithLength(data, bytesLength)
		data = data.slice(content.length + bytesLength)

		return content
	}
}

export async function verifyCertificateSignature({
	signature,
	algorithm,
	publicKey,
	hellos,
	cipherSuite
}: VerifySignatureOptions) {
	const { verify } = SUPPORTED_SIGNATURE_ALGS_MAP[algorithm]
	const data = await getSignatureData()
	const verified = await verify(data, signature, publicKey)

	if(!verified) {
		throw new Error(`${algorithm} signature verification failed`)
	}

	async function getSignatureData() {
		const handshakeHash = await getHash(hellos, cipherSuite)
		const content = concatenateUint8Arrays([
			new Uint8Array(64).fill(0x20),
			CERT_VERIFY_TXT,
			new Uint8Array([0]),
			handshakeHash
		])

		return content
	}
}

export async function verifyCertificateChain(
	chain: X509Certificate[],
	host: string,
	additionalRootCAs?: X509Certificate[]
) {
	const rootCAs = [
		...ROOT_CAS,
		...additionalRootCAs || []
	]

	for(let i = 0; i < chain.length - 1; i++) {
		const issuer = chain[i + 1]
		if(!issuer.isIssuer(chain[i])) {
			throw new Error(`Certificate ${i} was not issued by certificate ${i + 1}`)
		}

		if(!(await issuer.verifyIssued(chain[i]))) {
			throw new Error(`Certificate ${i} issue verification failed`)
		}
	}

	const root = chain[chain.length - 1]
	const rootIssuer = rootCAs.find(r => r.isIssuer(root))
	if(!rootIssuer) {
		throw new Error('Root CA not found. Could not verify certificate')
	}

	const verified = await rootIssuer.verifyIssued(root)
	if(!verified) {
		throw new Error('Root CA did not issue certificate')
	}
}