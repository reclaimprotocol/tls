export type PrivateKey = string

/**
 * public key in DER format
 * DER => Uint8Array
 */
export type CertificatePublicKey = Uint8Array

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type X509Certificate<T = any> = {
	internal: T
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