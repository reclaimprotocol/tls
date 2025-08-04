import { setCryptoImplementation } from '../crypto/index.ts'
import { pureJsCrypto } from '../crypto/pure.ts'

setCryptoImplementation(pureJsCrypto)