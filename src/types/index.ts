import type { X509Certificate } from './x509.ts'

export * from './x509.ts'
export * from './tls.ts'
export * from './crypto.ts'
export * from './logger.ts'

declare global {
	const TLS_ADDITIONAL_ROOT_CA_LIST: string[]
	/**
	 * Store fetched intermediate certificates typically fetched via
	 * the AIA extension here to avoid refetching
	 */
	const TLS_INTERMEDIATE_CA_CACHE: { [url: string]: X509Certificate }
}