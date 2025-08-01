export type PrivateKey = string

export type CertificatePublicKey = {
	/**
	 * public key in DER format
	 * DER => Uint8Array
	 */
	buffer: Uint8Array

	algorithm: string
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type X509Certificate<T = any> = {
	internal: T
	/**
	 * Checks new Date() is in the validity period
	 * of the certificate, basically outside notBefore and notAfter
	 */
	isWithinValidity(): boolean
	getSubjectField(key: string): string[]
	getAlternativeDNSNames(): string[]
	isIssuer(ofCert: X509Certificate<T>): boolean
	getPublicKey(): CertificatePublicKey
	getPublicKeyAlgorithm(): Algorithm
	/**
	 * verify this certificate issued the certificate passed
	 * @param otherCert the supposedly issued certificate to verify
	 * */
	verifyIssued(otherCert: X509Certificate<T>): boolean | Promise<boolean>

	serialiseToPem(): string
}