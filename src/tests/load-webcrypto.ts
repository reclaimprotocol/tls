import { setCryptoImplementation } from '../crypto/index.ts'
import { webcryptoCrypto } from '../crypto/webcrypto.ts'

setCryptoImplementation(webcryptoCrypto)