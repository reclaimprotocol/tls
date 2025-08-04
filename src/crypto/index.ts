import type { Crypto } from '../types/index.ts'

export const crypto = {} as Crypto<unknown>

export function setCryptoImplementation(impl: Crypto<unknown>) {
	Object.assign(crypto, impl)
}