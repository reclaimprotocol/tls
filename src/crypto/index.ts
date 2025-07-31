import type { Crypto } from '../types'

export const crypto = {} as Crypto<unknown>

export function setCryptoImplementation(impl: Crypto<unknown>) {
	Object.assign(crypto, impl)
}