import { setCryptoImplementation } from '../crypto/index.ts'
import { pureJsCrypto } from '../crypto/pure-js.ts'

setCryptoImplementation(pureJsCrypto)