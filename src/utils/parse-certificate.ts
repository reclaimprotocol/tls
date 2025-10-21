import './additional-root-cas.js'
import { crypto } from '../crypto/index.ts'
import type { CertificatePublicKey, CipherSuite, Key, Logger, TLSProcessContext, X509Certificate } from '../types/index.ts'
import { SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_SIGNATURE_ALGS, SUPPORTED_SIGNATURE_ALGS_MAP } from './constants.ts'
import { getHash } from './decryption-utils.ts'
import { areUint8ArraysEqual, asciiToUint8Array, concatenateUint8Arrays } from './generics.ts'
import { MOZILLA_ROOT_CA_LIST } from './mozilla-root-cas.ts'
import { expectReadWithLength, packWithLength } from './packets.ts'
import { defaultFetchCertificateBytes, loadX509FromDer, loadX509FromPem } from './x509.ts'

type VerifySignatureOptions = {
	signature: Uint8Array
	algorithm: keyof typeof SUPPORTED_SIGNATURE_ALGS_MAP
	publicKey: CertificatePublicKey
	signatureData: Uint8Array
}

const CERT_VERIFY_TXT = asciiToUint8Array('TLS 1.3, server CertificateVerify')
let ROOT_CAS: X509Certificate[] | undefined

export function parseCertificates(
	data: Uint8Array,
	{ version }: TLSProcessContext
) {
	// context, kina irrelevant
	const ctx = version === 'TLS1_3' ? read(1)[0] : 0
	// the data itself
	data = readWLength(3)

	const certificates: X509Certificate[] = []
	while(data.length) {
		// the certificate data
		const cert = readWLength(3)
		const certObj = loadX509FromDer(cert)

		certificates.push(certObj)
		if(version === 'TLS1_3') {
			// extensions
			readWLength(2)
		}
	}

	return { certificates, ctx }

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
	signatureData,
}: VerifySignatureOptions) {
	const { algorithm: cryptoAlg } = SUPPORTED_SIGNATURE_ALGS_MAP[algorithm]
	const pubKey = await crypto.importKey(cryptoAlg, publicKey.buffer, 'public')
	const verified = await crypto.verify(cryptoAlg, {
		data: signatureData,
		signature,
		publicKey: pubKey
	})

	if(!verified) {
		throw new Error(`${algorithm} signature verification failed`)
	}
}

export async function getSignatureDataTls13(
	hellos: Uint8Array[] | Uint8Array, cipherSuite: CipherSuite
) {
	const handshakeHash = await getHash(hellos, cipherSuite)
	return concatenateUint8Arrays([
		new Uint8Array(64).fill(0x20),
		CERT_VERIFY_TXT,
		new Uint8Array([0]),
		handshakeHash
	])
}

type Tls12SignatureDataOpts = {
	clientRandom: Uint8Array
	serverRandom: Uint8Array
	curveType: keyof typeof SUPPORTED_NAMED_CURVE_MAP
	publicKey: Key
}

export async function getSignatureDataTls12(
	{
		clientRandom,
		serverRandom,
		curveType,
		publicKey,
	}: Tls12SignatureDataOpts,
) {
	const publicKeyBytes = await crypto.exportKey(publicKey)
	return concatenateUint8Arrays([
		clientRandom,
		serverRandom,
		concatenateUint8Arrays([
			new Uint8Array([3]),
			SUPPORTED_NAMED_CURVE_MAP[curveType].identifier,
		]),
		packWithLength(publicKeyBytes)
			// pub key is packed with 1 byte length
			.slice(1)
	])
}

export async function verifyCertificateChain(
	chain: X509Certificate[],
	host: string,
	logger: Logger,
	fetchCertificateBytes = defaultFetchCertificateBytes,
	additionalRootCAs?: X509Certificate[]
) {
	const rootCAs = [
		...loadRootCAs(),
		...(additionalRootCAs || [])
	]

	const leaf = chain[0]
	const commonNames = [
		...leaf.getSubjectField('CN'),
		...leaf.getAlternativeDNSNames()
	]
	if(!commonNames.some(cn => matchHostname(host, cn))) {
		throw new Error(`Certificate is not for host ${host}`)
	}

	chain = [...chain] // clone to allow appending fetched certs
	for(let i = 0; i < chain.length; i++) {
		const cert = chain[i]
		const cn = cert.getSubjectField('CN')
		if(!cert.isWithinValidity()) {
			throw new Error(`Certificate ${cn} (i: ${i}) is outside validity`)
		}

		// look in our chain for issuer
		let issuer = findIssuer(chain.slice(i + 1), cert)
		// if not found, check in our root CAs
		if(!issuer) {
			issuer = findIssuer(rootCAs, cert)
		}

		// if not found, we'll try fetching it via AIA extension
		if(!issuer) {
			const aiaExt = cert.getAIAExtension()
			if(!aiaExt) {
				throw new Error(`Missing issuer for certificate ${cn} (i: ${i})`)
			}

			if(TLS_INTERMEDIATE_CA_CACHE?.[aiaExt]) {
				issuer = TLS_INTERMEDIATE_CA_CACHE[aiaExt]
			} else {
				logger.debug(
					{ aiaExt, cn },
					'fetching issuer certificate via AIA extension'
				)

				const bytes = await fetchCertificateBytes(aiaExt)
				issuer = await loadX509FromPem(bytes)
				// we'll need to verify this cert below too
				chain.push(issuer)

				TLS_INTERMEDIATE_CA_CACHE[aiaExt] = issuer
			}
		}

		if(!issuer.isWithinValidity()) {
			throw new Error(`Issuer Cert ${cn} is not within validity period`)
		}

		if(!(await issuer.verifyIssued(cert))) {
			const icn = issuer.getSubjectField('CN')
			throw new Error(
				`Verification of ${cn} failed by issuer ${icn} (i: ${i})`
			)
		}
	}
}

function findIssuer(chain: X509Certificate[], cert: X509Certificate) {
	for(const element of chain) {
		if(element.isIssuer(cert)) {
			return element
		}
	}
}

/**
 * Checks if a hostname matches a common name
 * @param host the hostname, eg. "google.com"
 * @param commonName the common name from the certificate,
 * 	eg. "*.google.com", "google.com"
 */
function matchHostname(host: string, commonName: string) {
	// write a regex to match the common name
	// and check if it matches the hostname
	const hostComps = host.split('.')
	const cnComps = commonName.split('.')

	if(cnComps.length !== hostComps.length) {
		// can ignore the first component if it's a wildcard
		if(
			cnComps[0] === '*'
			&& cnComps.length === hostComps.length + 1
		) {
			cnComps.shift()
		} else {
			return false
		}
	}

	return hostComps.every((comp, i) => (
		comp === cnComps[i]
			|| cnComps[i] === '*'
	))
}

function loadRootCAs() {
	if(ROOT_CAS) {
		return ROOT_CAS
	}

	ROOT_CAS = MOZILLA_ROOT_CA_LIST.map(loadX509FromPem)
	if(typeof TLS_ADDITIONAL_ROOT_CA_LIST !== 'undefined') {
		ROOT_CAS.push(...TLS_ADDITIONAL_ROOT_CA_LIST.map(loadX509FromPem))
	}

	return ROOT_CAS
}