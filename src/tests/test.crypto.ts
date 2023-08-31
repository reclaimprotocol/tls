import { computeBinderSuffix, packPresharedKeyExtension } from '../utils/client-hello'
import { SUPPORTED_SIGNATURE_ALGS_MAP } from '../utils/constants'
import { expectReadWithLength } from '../utils/packets'
import { verifyCertificateChain, verifyCertificateSignature } from '../utils/parse-certificate'
import { getPskFromTicket, parseSessionTicket } from '../utils/session-ticket'
import { TLSPresharedKey } from '../types'
import { loadX509FromPem } from '../utils/x509'
import { CURVES } from '../utils/curve'
import { computeSharedKeys } from '../utils/decryption-utils'
import { bufferFromHexStringWithWhitespace, toHexStringWithWhitespace } from '../utils/generics'
import { expectBuffsEq } from './utils'

const curve = CURVES['X25519']

describe('Crypto Tests', () => {

	// test case from: https://tls13.xargs.org
	it('should correctly compute handshake keys', () => {
		const masterKey = curve.calculateSharedKey(
			Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex'),
			Buffer.from('9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615', 'hex'),
		)

		expect(toHexStringWithWhitespace(masterKey, '')).toEqual(
			'df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624'
		)

		const result = computeSharedKeys({
			hellos: [
				bufferFromHexStringWithWhitespace(
					'01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54'
				),
				bufferFromHexStringWithWhitespace(
					'02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15'
				),
			],
			masterSecret: masterKey,
			secretType: 'hs',
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256'
		})

		expect(toHexStringWithWhitespace(result.masterSecret, '')).toEqual(
			'fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a'
		)
		expect(toHexStringWithWhitespace(result.clientSecret, '')).toEqual(
			'39df949cf723c7b3a398bfc9902837f9e762c632e868131b19d946b9ec01bb78'
		)
		expect(toHexStringWithWhitespace(result.serverIv, '')).toEqual(
			'151187a208b0f49ba2a81084'
		)
	})

	it('should correctly compute provider keys', () => {
		const masterKey = curve.calculateSharedKey(
			Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex'),
			Buffer.from('9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615', 'hex'),
		)

		expect(toHexStringWithWhitespace(masterKey, '')).toEqual(
			'df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624'
		)

		const hellos = [
			bufferFromHexStringWithWhitespace(
				'01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54'
			),
			bufferFromHexStringWithWhitespace(
				'02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15'
			),
			bufferFromHexStringWithWhitespace(
				'08 00 00 02 00 00'
			),
			bufferFromHexStringWithWhitespace(
				'0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00'
			),
			bufferFromHexStringWithWhitespace(
				'0f 00 01 04 08 04 01 00 5c bb 24 c0 40 93 32 da a9 20 bb ab bd b9 bd 50 17 0b e4 9c fb e0 a4 10 7f ca 6f fb 10 68 e6 5f 96 9e 6d e7 d4 f9 e5 60 38 d6 7c 69 c0 31 40 3a 7a 7c 0b cc 86 83 e6 57 21 a0 c7 2c c6 63 40 19 ad 1d 3a d2 65 a8 12 61 5b a3 63 80 37 20 84 f5 da ec 7e 63 d3 f4 93 3f 27 22 74 19 a6 11 03 46 44 dc db c7 be 3e 74 ff ac 47 3f aa ad de 8c 2f c6 5f 32 65 77 3e 7e 62 de 33 86 1f a7 05 d1 9c 50 6e 89 6c 8d 82 f5 bc f3 5f ec e2 59 b7 15 38 11 5e 9c 8c fb a6 2e 49 bb 84 74 f5 85 87 b1 1b 8a e3 17 c6 33 e9 c7 6c 79 1d 46 62 84 ad 9c 4f f7 35 a6 d2 e9 63 b5 9b bc a4 40 a3 07 09 1a 1b 4e 46 bc c7 a2 f9 fb 2f 1c 89 8e cb 19 91 8b e4 12 1d 7e 8e d0 4c d5 0c 9a 59 e9 87 98 01 07 bb bf 29 9c 23 2e 7f db e1 0a 4c fd ae 5c 89 1c 96 af df f9 4b 54 cc d2 bc 19 d3 cd aa 66 44 85 9c'
			),
			bufferFromHexStringWithWhitespace(
				'14 00 00 30 7e 30 ee cc b6 b2 3b e6 c6 ca 36 39 92 e8 42 da 87 7e e6 47 15 ae 7f c0 cf 87 f9 e5 03 21 82 b5 bb 48 d1 e3 3f 99 79 05 5a 16 0c 8d bb b1 56 9c'
			)
		]

		const { masterSecret } = computeSharedKeys({
			hellos: hellos.slice(0, 2),
			masterSecret: masterKey,
			secretType: 'hs',
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
		})

		const result = computeSharedKeys({
			hellos,
			masterSecret,
			secretType: 'ap',
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256'
		})

		expect(result.serverIv.toString('hex')).toEqual(
			'a5e665c5599c95eeab6eb657'
		)
		expect(result.clientEncKey.toString('hex')).toEqual(
			'40c54418e38e52d5b976c0feca905eb8261604c2efcfabad39a060ddb7ab4bc8'
		)
	})

	// from: https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors
	it('should parse a session ticket correctly', () => {
		const ticketPacked = bufferFromHexStringWithWhitespace(
			`04 00 00 c9 00 00 00 1e fa d6 aa
			c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
			00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c
			49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
			72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28
			27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25
			a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c
			5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6
			17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50
			5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
			04 00 00 04 00`,
		)


		const parsed = parseSessionTicket(
			// skip the first byte, which is the packet type
			// and read the next 3 bytes as the length
			// which should give us the session ticket
			expectReadWithLength(ticketPacked.slice(1), 3)
		)
		expect(Array.from(parsed.nonce)).toEqual([0, 0])

		const ticketData = getPskFromTicket(parsed, {
			masterKey: bufferFromHexStringWithWhitespace(
				`18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
				47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19`
			),
			hellos: bufferFromHexStringWithWhitespace(
				`20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26
				84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d`
			),
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
		})

		const expectedExtBytes = bufferFromHexStringWithWhitespace(`
			00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
			00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
			ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
			82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
			1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
			37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
			90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
			ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
			e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
			c5 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
			ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d
		`)

		const helloPrefix = bufferFromHexStringWithWhitespace(`
		 01 00 01 fc 03 03 1b c3 ce b6 bb
         e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41
         9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00
         00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00
         14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04
         00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2
         66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b
         00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03
         06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05
         02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af
         4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf
         1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60
         97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61
         be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4
         d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2
         67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb
         f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41
         ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57
         fa d6 aa cb
		`)
		const ext = packPresharedKeyExtension(ticketData)
		const binder = computeBinderSuffix(helloPrefix, ticketData)
		binder.copy(ext, ext.length - binder.length)

		expectBuffsEq(ext, expectedExtBytes)
	})

	// from: https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors
	it('should generate the correct resume handshake keys', () => {
		const ticket: Pick<TLSPresharedKey, 'earlySecret'> = {
			earlySecret: bufferFromHexStringWithWhitespace(
				'9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c'
			)
		}

		const sharedkey = curve.calculateSharedKey(
			bufferFromHexStringWithWhitespace(`de 5b 44 76 e7 b4 90 b2 65 2d 33 8a cb
			f2 94 80 66 f2 55 f9 44 0e 23 b9 8f c6 98 35 29 8d c1 07`),
			bufferFromHexStringWithWhitespace(`e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
			6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b`)
		)

		const clientHello = bufferFromHexStringWithWhitespace(`
		01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff
		93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76
		48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00
		09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
		00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00
		26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
		6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00
		00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
		03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
		02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
		00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
		00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
		ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
		82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
		1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
		37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
		90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
		ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
		e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
		cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
		ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d
		`)

		const serverHello = bufferFromHexStringWithWhitespace(`
		 02 00 00 5c 03 03 3c cf d2 de c8 90 22
         27 63 47 2a e8 13 67 77 c9 d7 35 87 77 bb 66 e9 1e a5 12 24 95
         f5 59 ea 2d 00 13 01 00 00 34 00 29 00 02 00 00 00 33 00 24 00
         1d 00 20 12 17 61 ee 42 c3 33 e1 b9 e7 7b 60 dd 57 c2 05 3c d9
         45 12 ab 47 f1 15 e8 6e ff 50 94 2c ea 31 00 2b 00 02 03 04
		`)

		const keys = computeSharedKeys({
			masterSecret: sharedkey,
			earlySecret: ticket.earlySecret,
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
			secretType: 'hs',
			hellos: [clientHello, serverHello]
		})

		expect(toHexStringWithWhitespace(keys.serverEncKey)).toEqual(
			'a6 7e 92 e7 8c 02 8e 0c 52 33 fb 0b 3c e3 df 6a f0 39 62 eb 06 bc 0c 92 93 d8 4a 49 ca 44 4f f4'
		)
		expect(toHexStringWithWhitespace(keys.clientIv)).toEqual(
			'eb 50 c1 6b e7 65 4a bf 99 dd 06 d9'
		)
	})

	it('should verify certificate chain', async() => {
		const certificateChain = [
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIG3jCCBcagAwIBAgIQA21fAAb+/uCxIvTiXuyiXDANBgkqhkiG9w0BAQsFADBZ
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE
aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjMw
NDIxMDAwMDAwWhcNMjQwNDIzMjM1OTU5WjBmMQswCQYDVQQGEwJVUzETMBEGA1UE
CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMM
R2l0SHViLCBJbmMuMRMwEQYDVQQDEwpnaXRodWIuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAn8kVwly5JONuqwX4TH3j2C8nuBA04+MVhYpF/7Dq
QUgjWygm5TeGIh1DwJ/3H2SxA60gWO/iCnWmobk4LzFh9j02DEL7HRG2XPp1o0Rk
6dFHLI4wYpPtjvEtbukFQLOouMoUb2GgEJnIje0cVHTX3H/0VQr/cfjUNhAhjHAo
2DkcRqSQBWO+F/yd66hee1ZHaeXCCdy3skx2jkbkmka79tQhTpm2giL/LVpDz86I
L2IamDAFqGF9jn7LRLD81WZPP7djfhyVwah3wxPTQVTw+P57AcbIvdZ7C56fBXNW
rnyBggmOSL2IWCKLh9dYs/jNr4oKNEw5ZNtQiPDvVgZO2wIDAQABo4IDkzCCA48w
HwYDVR0jBBgwFoAUdIWAwGbH3zfez70pN6oDHb7tzRcwHQYDVR0OBBYEFKscsqJB
CZW7WQ2meqSHLC1EEJYjMCUGA1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3dy5naXRo
dWIuY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwgZ8GA1UdHwSBlzCBlDBIoEagRIZCaHR0cDovL2NybDMuZGlnaWNlcnQu
Y29tL0RpZ2lDZXJ0R2xvYmFsRzJUTFNSU0FTSEEyNTYyMDIwQ0ExLTEuY3JsMEig
RqBEhkJodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRM
U1JTQVNIQTI1NjIwMjBDQTEtMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAn
BggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGHBggrBgEF
BQcBAQR7MHkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBR
BggrBgEFBQcwAoZFaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
R2xvYmFsRzJUTFNSU0FTSEEyNTYyMDIwQ0ExLTEuY3J0MAkGA1UdEwQCMAAwggF+
BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB3AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOze
w1FIWUZxH7WbAAABh6S+BYAAAAQDAEgwRgIhAPI4u66HgYy0TIZt0IzE1hv90NlS
KWNWNLojExb5RSfdAiEA4Zr5DJW0qHnyVfXfkhqi1RM/jsFy45ZYrdcvA5OlDzIA
dQBz2Z6JG0yWeKAgfUed5rLGHNBRXnEZKoxrgBB6wXdytQAAAYekvgXCAAAEAwBG
MEQCICTXRaSSsFD6WLYYeeK09QfOlz+Cm8fZKB6JJHQ5TjhBAiBPPipzT03NzSv8
ruolGamCZetcUqfsJtkVnDsiX/fBSwB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0s
gdm7v6s52IRzAAABh6S+BZQAAAQDAEcwRQIhAJvQ68TFgxUGNH1Affes4t4Tl30v
EVEz2cjPAV2fAgoyAiAoCyIdgS4lVmWUQgPHXHG9y4DLV8Yf6ZPGhJ/XUUuIuTAN
BgkqhkiG9w0BAQsFAAOCAQEAo2Xtv6+ZPkXca/nY7hYA03ZQ4I+5HT0dzQC8cXD5
H4k8UF0SZ87Lqhoucrp8ja1BJQAc99neCI/swiVafTBGhRVBpZRGM3DiSOXNEHzZ
Cdg7Yldv6FMkiI3cEFjwaHdRTEYJyHYsnchTcfMmbCAsgg36vPZ+lTj+cyy9OUKh
npUaMGmHh+NTPcZpE2RraLUq94i1DTT6v50K7aKTtSXUKUgy7VINa6FSlloEaTP/
9KuUc8CvtALrs5e9klIudjcc9zdXHJRAFlHEA8vOkyFIq9YaoQN9zDhkBQA+/W/R
8LpXmrL3Mz0RBef4HTPV1cR2Qqkq7hI+QrB+uL+GWp36kw==
-----END CERTIFICATE-----`,
			),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIEyDCCA7CgAwIBAgIQDPW9BitWAvR6uFAsI8zwZjANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0yMTAzMzAwMDAwMDBaFw0zMTAzMjkyMzU5NTlaMFkxCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxMzAxBgNVBAMTKkRpZ2lDZXJ0IEdsb2Jh
bCBHMiBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMz3EGJPprtjb+2QUlbFbSd7ehJWivH0+dbn4Y+9lavyYEEV
cNsSAPonCrVXOFt9slGTcZUOakGUWzUb+nv6u8W+JDD+Vu/E832X4xT1FE3LpxDy
FuqrIvAxIhFhaZAmunjZlx/jfWardUSVc8is/+9dCopZQ+GssjoP80j812s3wWPc
3kbW20X+fSP9kOhRBx5Ro1/tSUZUfyyIxfQTnJcVPAPooTncaQwywa8WV0yUR0J8
osicfebUTVSvQpmowQTCd5zWSOTOEeAqgJnwQ3DPP3Zr0UxJqyRewg2C/Uaoq2yT
zGJSQnWS+Jr6Xl6ysGHlHx+5fwmY6D36g39HaaECAwEAAaOCAYIwggF+MBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHSFgMBmx9833s+9KTeqAx2+7c0XMB8G
A1UdIwQYMBaAFE4iVCAYlebjbuYP+vq5Eu0GF485MA4GA1UdDwEB/wQEAwIBhjAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdgYIKwYBBQUHAQEEajBoMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKG
NGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RH
Mi5jcnQwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
L0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDA9BgNVHSAENjA0MAsGCWCGSAGG/WwC
ATAHBgVngQwBATAIBgZngQwBAgEwCAYGZ4EMAQICMAgGBmeBDAECAzANBgkqhkiG
9w0BAQsFAAOCAQEAkPFwyyiXaZd8dP3A+iZ7U6utzWX9upwGnIrXWkOH7U1MVl+t
wcW1BSAuWdH/SvWgKtiwla3JLko716f2b4gp/DA/JIS7w7d7kwcsr4drdjPtAFVS
slme5LnQ89/nD/7d+MS5EHKBCQRfz5eeLjJ1js+aWNJXMX43AYGyZm0pGrFmCW3R
bpD0ufovARTFXFZkAdl9h6g4U5+LXUZtXMYnhIHUfoyMo5tS58aI7Dd8KvvwVVo4
chDYABPPTHPbqjc1qCmBaZx2vN4Ye5DUys/vZwP9BFohFrH/6j/f3IL16/RZkiMN
JCqVJUzKoZHm1Lesh3Sz8W2jmdv51b2EQJ8HmA==
-----END CERTIFICATE-----`)
		]

		await verifyCertificateChain(certificateChain, '')
	})

	it('should verify RSA PSS certificate signature', async() => {
		await verifyCertificateSignature({
			signature: Buffer.from(
				'kfFzHaE6OFbceLjis2I4orufzHZbpQiG+jkq6aa25q6NsJSfITK9zRk017+hXApM+XezMKCNbPYAmHD183w8Be3HjjiCcVg8mzrq9YoMsmZhpSF1KlBY6uSG1/GUnIeu+su/bJzX4ujGoStmAFPYk2hOiKZJe8YwMNhuPJa65GKKQ1H3bKcs5af79FmqUGMNBEyhoLnoBoHrXLPNNPtAQB+Mk/rot8fP3+BIHnrmtExT4FgQM9AbF34e91QSXIagoYMzsW423T0/E3tM4u5E4VXXcdzWFWkT23ynmLcgoWgMTijxEL9xdejF2LhMrUxioELw13WAW2syA2yPIBLj9g==',
				'base64'
			),
			algorithm: 'RSA_PSS_RSAE_SHA256',
			publicKey: Buffer.from(
				'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjbkuJeiviTDDAWAUdWfxCGz3zWLGOj0O0eEi5DayefzZuinaGrBXyZT4KpDfz/wiw64H/PZHt2ppNWEMPt0jTs0p3DQLbXIFXLWmgb06sBVyjggTZKSReDre5Ze/KymBsrs1BTeRtkWScXfgJD99o8zqOhSGjy51Ce7nR8B77sfqGjyrvsuew93TtXao8XVBCl0jebT/tG/Qh2wkolvKlV2b9gvafvUoMkqT50cbJVD1dqZvJNukbro9wareaoeEPmEmsJaplkMzXTJDU4jYvBYmp2dHq0/BMepNtVpVFrTpLQReaI9jjZ40D25F/zBkapipf4unKsiPXff0ABPSwIDAQAB',
				'base64'
			),
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
			hellos: [
				'AQAAtAMDaiLWbRflcm3mBnM7qsSX6wOtsq4Vz79ei4kqhGB6MfYgwePTomJusJJCqppiDkfnRVz71EWXKlpcXelIUbiSMmsABBMCEwEBAABnAAAAEwARAAAOYXBpLmdpdGh1Yi5jb20ACgAIAAYAHQAYABcAIwAAACsAAwIDBAANAAQAAggEAC0AAwIAAQAzACYAJAAdACCiuv5ieC3NBzopklWgG5Bd9ck/WOHsHWenjVqjsbbzCg==',
				'AgAAdgMDX5xwfc47PuS+9tfLPR0MmhylFoIafu7zhsoIIaNdF54gwePTomJusJJCqppiDkfnRVz71EWXKlpcXelIUbiSMmsTAQAALgArAAIDBAAzACQAHQAgsl69ar/SE/WjwbCAZr08+X/SEL3DOvqXZy1c+8H4WEU=',
				'CAAABgAEAAAAAA==',
				'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'
			]
				.map(str => Buffer.from(str, 'base64'))
		})
	})

	it('should verify ECDSA certificate signature', async() => {
		const result = await SUPPORTED_SIGNATURE_ALGS_MAP['ECDSA_SECP256R1_SHA256'].verify(
			Buffer.from('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIHNlcnZlciBDZXJ0aWZpY2F0ZVZlcmlmeQC5foSrDb7/5Mm22rnkpcsJhk6Vab3ac3oaDzC7OBJkRQ==', 'base64'),
			Buffer.from('MEMCHwTtod6IPxR0cbg+ilX/whVTMRTlYJtdsdV8HU/PcFkCIEoSjIw7WkUVTqTQVOHx7F8ZX51A0x87o0C9iMUBt292', 'base64'),
			Buffer.from('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdKiaa4DZW9iBPmRsSA82paZ2rmAsjw/Z2XCzJP8TxPNAP4oeMVQV6M/LwQifIvgIgDB5WVwG9dyjExySuR517A==', 'base64')
		)
		expect(result).toBe(true)

		const result2 = await SUPPORTED_SIGNATURE_ALGS_MAP['ECDSA_SECP256R1_SHA256'].verify(
			Buffer.from('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIHNlcnZlciBDZXJ0aWZpY2F0ZVZlcmlmeQDu1MWPkhDhVy7Z0rZyYhBUJ2kmgoMHXHUybDNsHNhzeg==', 'base64'),
			Buffer.from('MEUCIGY4ojr/wPhpFU8ez8CL6RmT3Hx3Ge/UCdpw6SfnjmNJAiEA1e6rj9nKva8jnlSGWt6/I7lKjbK5uzvw/N9xFHW9jrM=', 'base64'),
			Buffer.from('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOLb2tA+FNKI4Klr5hE8x0yEHekfhJhxkj2nvjlrQYEhtRodEupmk/GRBOYQd7VpU8W/Yv6UbderjQlidaTtGxg==', 'base64')
		)
		expect(result2).toBe(true)
	})
})