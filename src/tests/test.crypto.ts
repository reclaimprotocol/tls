import { crypto } from '../crypto'
import { TLSPresharedKey } from '../types'
import { computeBinderSuffix, packPresharedKeyExtension } from '../utils'
import { computeSharedKeys, computeSharedKeysTls12 } from '../utils'
import { toHexStringWithWhitespace } from '../utils'
import { expectReadWithLength } from '../utils'
import { getSignatureDataTls13, verifyCertificateChain, verifyCertificateSignature } from '../utils'
import { getPskFromTicket, parseSessionTicket } from '../utils'
import { encryptWrappedRecord } from '../utils'
import { loadX509FromPem } from '../utils'
import { bufferFromHexStringWithWhitespace, expectBuffsEq } from './utils'

const curve = 'X25519'

describe('Crypto Tests', () => {

	// test case from: https://tls13.xargs.org
	it('should correctly compute handshake keys', async() => {
		const masterKey = await crypto.calculateSharedSecret(
			curve,
			await crypto.importKey(
				curve,
				Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex'),
				'private'
			),
			await crypto.importKey(
				curve,
				Buffer.from('9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615', 'hex'),
				'public'
			),
		)

		expect(toHexStringWithWhitespace(masterKey, '')).toEqual(
			'df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624'
		)

		const result = await computeSharedKeys({
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

	// from: https://tls12.xargs.org
	it('should correctly compute handshake keys TLS1.2', async() => {
		const preMasterSecret = bufferFromHexStringWithWhitespace(
			'df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624'
		)

		const result = await computeSharedKeysTls12({
			preMasterSecret,
			clientRandom: bufferFromHexStringWithWhitespace(
				'00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f'
			),
			serverRandom: bufferFromHexStringWithWhitespace(
				'70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'
			),
			cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
		})

		const clientEncKey = await crypto.exportKey(result.clientEncKey)
		const serverEncKey = await crypto.exportKey(result.serverEncKey)
		const clientMacKey = await crypto.exportKey(result.clientMacKey!)
		expect(
			toHexStringWithWhitespace(result.masterSecret, '')
		).toEqual(
			'916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c'
		)
		expect(toHexStringWithWhitespace(clientEncKey, '')).toEqual(
			'f656d037b173ef3e11169f27231a84b6'
		)
		expect(toHexStringWithWhitespace(serverEncKey, '')).toEqual(
			'752a18e7a9fcb7cbcdd8f98dd8f769eb'
		)
		expect(toHexStringWithWhitespace(clientMacKey, '')).toEqual(
			'1b7d117c7d5f690bc263cae8ef60af0f1878acc2'
		)
	})

	it('should encrypt data TLS1.2', async() => {
		const { ciphertext } = await encryptWrappedRecord(
			bufferFromHexStringWithWhitespace(
				'14 00 00 0c cf 91 96 26 f1 36 0c 53 6a aa d7 3a'
			),
			{
				key: await crypto.importKey(
					'AES-128-CBC',
					bufferFromHexStringWithWhitespace(
						'f656d037b173ef3e11169f27231a84b6'
					)
				),
				macKey: await crypto.importKey(
					'SHA-1',
					bufferFromHexStringWithWhitespace(
						'1b7d117c7d5f690bc263cae8ef60af0f1878acc2'
					)
				),
				iv: bufferFromHexStringWithWhitespace(
					'40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f'
				),
				recordNumber: 0,
				cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
				recordHeaderOpts: { type: 'HELLO', },
				version: 'TLS1_2'
			}
		)

		expect(
			toHexStringWithWhitespace(ciphertext)
		).toEqual(
			'40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 22 7b c9 ba 81 ef 30 f2 a8 a7 8f f1 df 50 84 4d 58 04 b7 ee b2 e2 14 c3 2b 68 92 ac a3 db 7b 78 07 7f dd 90 06 7c 51 6b ac b3 ba 90 de df 72 0f'
		)
	})

	it('should correctly compute provider keys', async() => {
		const masterKey = await crypto.calculateSharedSecret(
			curve,
			await crypto.importKey(
				curve,
				Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex'),
				'private'
			),
			await crypto.importKey(
				curve,
				Buffer.from('9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615', 'hex'),
				'public'
			)
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

		const { masterSecret } = await computeSharedKeys({
			hellos: hellos.slice(0, 2),
			masterSecret: masterKey,
			secretType: 'hs',
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
		})

		const result = await computeSharedKeys({
			hellos,
			masterSecret,
			secretType: 'ap',
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256'
		})
		const clientEncKey = await crypto.exportKey(result.clientEncKey)

		expect(toHexStringWithWhitespace(result.serverIv, '')).toEqual(
			'a5e665c5599c95eeab6eb657'
		)
		expect(toHexStringWithWhitespace(clientEncKey, '')).toEqual(
			'40c54418e38e52d5b976c0feca905eb8261604c2efcfabad39a060ddb7ab4bc8'
		)
	})

	// from: https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors
	it('should parse a session ticket correctly', async() => {
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

		const ticketData = await getPskFromTicket(parsed, {
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
		const binder = await computeBinderSuffix(helloPrefix, ticketData)
		ext.set(binder, ext.length - binder.length)

		expectBuffsEq(ext, expectedExtBytes)
	})

	// from: https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors
	it('should generate the correct resume handshake keys', async() => {
		const ticket: Pick<TLSPresharedKey, 'earlySecret'> = {
			earlySecret: bufferFromHexStringWithWhitespace(
				'9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c'
			)
		}

		const sharedkey = await crypto.calculateSharedSecret(
			curve,
			await crypto.importKey(
				curve,
				bufferFromHexStringWithWhitespace(`de 5b 44 76 e7 b4 90 b2 65 2d 33 8a cb
					f2 94 80 66 f2 55 f9 44 0e 23 b9 8f c6 98 35 29 8d c1 07`),
				'private'
			),
			await crypto.importKey(
				curve,
				bufferFromHexStringWithWhitespace(`e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
					6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b`),
				'public'
			)
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

		const keys = await computeSharedKeys({
			masterSecret: sharedkey,
			earlySecret: ticket.earlySecret,
			cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
			secretType: 'hs',
			hellos: [clientHello, serverHello]
		})
		const serverEncKey = await crypto.exportKey(keys.serverEncKey)

		expect(toHexStringWithWhitespace(serverEncKey)).toEqual(
			'a6 7e 92 e7 8c 02 8e 0c 52 33 fb 0b 3c e3 df 6a f0 39 62 eb 06 bc 0c 92 93 d8 4a 49 ca 44 4f f4'
		)
		expect(toHexStringWithWhitespace(keys.clientIv)).toEqual(
			'eb 50 c1 6b e7 65 4a bf 99 dd 06 d9'
		)
	})

	it('should verify certificate chain', async() => {
		const certificateChain = [
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIEozCCBEmgAwIBAgIQTij3hrZsGjuULNLEDrdCpTAKBggqhkjOPQQDAjCBjzEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5T
ZWN0aWdvIEVDQyBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMB4X
DTI0MDMwNzAwMDAwMFoXDTI1MDMwNzIzNTk1OVowFTETMBEGA1UEAxMKZ2l0aHVi
LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABARO/Ho9XdkY1qh9mAgjOUkW
mXTb05jgRulKciMVBuKB3ZHexvCdyoiCRHEMBfFXoZhWkQVMogNLo/lW215X3pGj
ggL+MIIC+jAfBgNVHSMEGDAWgBT2hQo7EYbhBH0Oqgss0u7MZHt7rjAdBgNVHQ4E
FgQUO2g/NDr1RzTK76ZOPZq9Xm56zJ8wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB
/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEkGA1UdIARCMEAw
NAYLKwYBBAGyMQECAgcwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNv
bS9DUFMwCAYGZ4EMAQIBMIGEBggrBgEFBQcBAQR4MHYwTwYIKwYBBQUHMAKGQ2h0
dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb0VDQ0RvbWFpblZhbGlkYXRpb25T
ZWN1cmVTZXJ2ZXJDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3Rp
Z28uY29tMIIBgAYKKwYBBAHWeQIEAgSCAXAEggFsAWoAdwDPEVbu1S58r/OHW9lp
LpvpGnFnSrAX7KwB0lt3zsw7CAAAAY4WOvAZAAAEAwBIMEYCIQD7oNz/2oO8VGaW
WrqrsBQBzQH0hRhMLm11oeMpg1fNawIhAKWc0q7Z+mxDVYV/6ov7f/i0H/aAcHSC
Ii/QJcECraOpAHYAouMK5EXvva2bfjjtR2d3U9eCW4SU1yteGyzEuVCkR+cAAAGO
Fjrv+AAABAMARzBFAiEAyupEIVAMk0c8BVVpF0QbisfoEwy5xJQKQOe8EvMU4W8C
IGAIIuzjxBFlHpkqcsa7UZy24y/B6xZnktUw/Ne5q5hCAHcATnWjJ1yaEMM4W2zU
3z9S6x3w4I4bjWnAsfpksWKaOd8AAAGOFjrv9wAABAMASDBGAiEA+8OvQzpgRf31
uLBsCE8ktCUfvsiRT7zWSqeXliA09TUCIQDcB7Xn97aEDMBKXIbdm5KZ9GjvRyoF
9skD5/4GneoMWzAlBgNVHREEHjAcggpnaXRodWIuY29tgg53d3cuZ2l0aHViLmNv
bTAKBggqhkjOPQQDAgNIADBFAiEAru2McPr0eNwcWNuDEY0a/rGzXRfRrm+6XfZe
SzhYZewCIBq4TUEBCgapv7xvAtRKdVdi/b4m36Uyej1ggyJsiesA
-----END CERTIFICATE-----`,
			),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIDqDCCAy6gAwIBAgIRAPNkTmtuAFAjfglGvXvh9R0wCgYIKoZIzj0EAwMwgYgx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJz
ZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQD
EyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE4MTEw
MjAwMDAwMFoXDTMwMTIzMTIzNTk1OVowgY8xCzAJBgNVBAYTAkdCMRswGQYDVQQI
ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoT
D1NlY3RpZ28gTGltaXRlZDE3MDUGA1UEAxMuU2VjdGlnbyBFQ0MgRG9tYWluIFZh
bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABHkYk8qfbZ5sVwAjBTcLXw9YWsTef1Wj6R7W2SUKiKAgSh16TwUwimNJE4xk
IQeV/To14UrOkPAY9z2vaKb71EijggFuMIIBajAfBgNVHSMEGDAWgBQ64QmG1M8Z
wpZ2dEl23OA1xmNjmjAdBgNVHQ4EFgQU9oUKOxGG4QR9DqoLLNLuzGR7e64wDgYD
VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMBsGA1UdIAQUMBIwBgYEVR0gADAIBgZngQwBAgEwUAYD
VR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVz
dEVDQ0NlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/
BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdEVD
Q0FkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1
c3QuY29tMAoGCCqGSM49BAMDA2gAMGUCMEvnx3FcsVwJbZpCYF9z6fDWJtS1UVRs
cS0chWBNKPFNpvDKdrdKRe+oAkr2jU+ubgIxAODheSr2XhcA7oz9HmedGdMhlrd9
4ToKFbZl+/OnFFzqnvOhcjHvClECEQcKmc8fmA==
-----END CERTIFICATE-----`),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIICjzCCAhWgAwIBAgIQXIuZxVqUxdJxVt7NiYDMJjAKBggqhkjOPQQDAzCBiDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl
eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT
JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMjAx
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
Ck5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUg
VVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlm
aWNhdGlvbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQarFRaqflo
I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng
o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXmjQjBAMB0G
A1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNVHQ8BAf8EBAMCAQYwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjA2Z6EWCNzklwBBHU6+4WMB
zzuqQhFkoJ2UOQIReVx7Hfpkue4WQrO/isIJxOzksU0CMQDpKmFHjFJKS04YcPbW
RNZu9YO6bVi9JNlWSOrvxKJGgYhqOkbRqZtNyWHa0V1Xahg=
-----END CERTIFICATE-----`)
		]

		await verifyCertificateChain(certificateChain, 'github.com')
	})

	it('should call out certificate not for host', async() => {
		const certs = [
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIAwgAICMDQwgAYCVR0AADAAMB4XDTE1MDExMTUwMTU7AAEXDTE4MDExMjExNDA6
AAAwADCAMIAGByqGSM49AgEGBSuBBAAmAAADAwBmTwAAAAAwgAYFKw4DAg4MAAAD
AwAxAAAA
-----END CERTIFICATE-----`)
		]

		await expect(
			verifyCertificateChain(certs, 'github.com')
		).rejects.toThrowError(
			'Certificate is not for host github.com'
		)
	})

	it('should verify RSA PSS certificate signature', async() => {
		const signatureData = await getSignatureDataTls13(
			[
				'AQAAtAMDaiLWbRflcm3mBnM7qsSX6wOtsq4Vz79ei4kqhGB6MfYgwePTomJusJJCqppiDkfnRVz71EWXKlpcXelIUbiSMmsABBMCEwEBAABnAAAAEwARAAAOYXBpLmdpdGh1Yi5jb20ACgAIAAYAHQAYABcAIwAAACsAAwIDBAANAAQAAggEAC0AAwIAAQAzACYAJAAdACCiuv5ieC3NBzopklWgG5Bd9ck/WOHsHWenjVqjsbbzCg==',
				'AgAAdgMDX5xwfc47PuS+9tfLPR0MmhylFoIafu7zhsoIIaNdF54gwePTomJusJJCqppiDkfnRVz71EWXKlpcXelIUbiSMmsTAQAALgArAAIDBAAzACQAHQAgsl69ar/SE/WjwbCAZr08+X/SEL3DOvqXZy1c+8H4WEU=',
				'CAAABgAEAAAAAA==',
				'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'
			]
				.map(str => Buffer.from(str, 'base64')),
			'TLS_CHACHA20_POLY1305_SHA256'
		)

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
			signatureData,
		})
	})

	it('should verify ECDSA certificate signature', async() => {
		const result = await crypto.verify(
			'ECDSA-SECP256R1-SHA256',
			{
				data: Buffer.from('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIHNlcnZlciBDZXJ0aWZpY2F0ZVZlcmlmeQC5foSrDb7/5Mm22rnkpcsJhk6Vab3ac3oaDzC7OBJkRQ==', 'base64'),
				signature: Buffer.from('MEMCHwTtod6IPxR0cbg+ilX/whVTMRTlYJtdsdV8HU/PcFkCIEoSjIw7WkUVTqTQVOHx7F8ZX51A0x87o0C9iMUBt292', 'base64'),
				publicKey: await crypto.importKey(
					'ECDSA-SECP256R1-SHA256',
					Buffer.from('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdKiaa4DZW9iBPmRsSA82paZ2rmAsjw/Z2XCzJP8TxPNAP4oeMVQV6M/LwQifIvgIgDB5WVwG9dyjExySuR517A==', 'base64'),
					'public'
				)
			}
		)
		expect(result).toBe(true)

		const result2 = await crypto.verify(
			'ECDSA-SECP256R1-SHA256',
			{
				data: Buffer.from('ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFRMUyAxLjMsIHNlcnZlciBDZXJ0aWZpY2F0ZVZlcmlmeQDu1MWPkhDhVy7Z0rZyYhBUJ2kmgoMHXHUybDNsHNhzeg==', 'base64'),
				signature: Buffer.from('MEUCIGY4ojr/wPhpFU8ez8CL6RmT3Hx3Ge/UCdpw6SfnjmNJAiEA1e6rj9nKva8jnlSGWt6/I7lKjbK5uzvw/N9xFHW9jrM=', 'base64'),
				publicKey: await crypto.importKey(
					'ECDSA-SECP256R1-SHA256',
					Buffer.from('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOLb2tA+FNKI4Klr5hE8x0yEHekfhJhxkj2nvjlrQYEhtRodEupmk/GRBOYQd7VpU8W/Yv6UbderjQlidaTtGxg==', 'base64'),
					'public'
				)
			}
		)
		expect(result2).toBe(true)
	})

	it('should verify certificate chain with incorrect order', async() => {
		const certificateChain = [
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIG/jCCBeagAwIBAgIQKPBugkD3/+URhZY+cQYKcTANBgkqhkiG9w0BAQsFADCB
ujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsT
H1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAy
MDE0IEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwG
A1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxTTAeFw0y
NDA0MDQxNTE1NTBaFw0yNTA0MzAxNTE1NDlaMIGUMQswCQYDVQQGEwJHQjEPMA0G
A1UEBxMGTG9uZG9uMRMwEQYLKwYBBAGCNzwCAQMTAkpFMRUwEwYDVQQKEwxFeHBl
cmlhbiBQTEMxHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9uMQ4wDAYDVQQF
EwU5MzkwNTEZMBcGA1UEAxMQdXNhLmV4cGVyaWFuLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAO8i4q2MH82f0z26g5EvHFFOEP2P0EYMpbPGAO6x
4I+a0M2b9/kwVUqRsD6J0s57AeNwt3zFI0AXJQbYyPxkz/UGS0a/vWp+1tWYAhbh
EJi8XJ3LuyevOHn408GYTT7O7cbSm401AnJj1jzFwgRCjPEAI0BipW5gqSV8cY0r
+80vVndCLlhq6cLEzqUvKoqlQ7x8qG38cOTgFTpEsJbgp8dGvPjwQ2bwYqDsOWNm
aF9bFFoYTPvuQBEEdyVfFUZQmdefiSBAnVI2F/77fAPmNabBxIdjALoj0ak4dtHf
UBOPPuZ3QtzIw3yYkDE3JFKzOamHjaakugG9W+3S0++G24MCAwEAAaOCAyIwggMe
MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNZ0EntaKwMXF9iHiyEoWvy2fHeiMB8G
A1UdIwQYMBaAFMP30LUqMK2vDZEhcDlU3byJcMc6MGgGCCsGAQUFBwEBBFwwWjAj
BggrBgEFBQcwAYYXaHR0cDovL29jc3AuZW50cnVzdC5uZXQwMwYIKwYBBQUHMAKG
J2h0dHA6Ly9haWEuZW50cnVzdC5uZXQvbDFtLWNoYWluMjU2LmNlcjAzBgNVHR8E
LDAqMCigJqAkhiJodHRwOi8vY3JsLmVudHJ1c3QubmV0L2xldmVsMW0uY3JsMDEG
A1UdEQQqMCiCEHVzYS5leHBlcmlhbi5jb22CFHd3dy51c2EuZXhwZXJpYW4uY29t
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
SwYDVR0gBEQwQjAHBgVngQwBATA3BgpghkgBhvpsCgECMCkwJwYIKwYBBQUHAgEW
G2h0dHBzOi8vd3d3LmVudHJ1c3QubmV0L3JwYTCCAX4GCisGAQQB1nkCBAIEggFu
BIIBagFoAHcA5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGOqa44
lwAABAMASDBGAiEAwglz3P9yr6qb9mnG5RIlffvIXZfpYQAyNSZnEG+UlngCIQCl
aWWkSq0JSEAK/N3M+HJRLwRaAhGzFmw1Fx7m5+T6TgB1AKLjCuRF772tm3447Udn
d1PXgluElNcrXhssxLlQpEfnAAABjqmuOLYAAAQDAEYwRAIgXXjkLjKtWU3I40HK
yQFqrovnWwFqnbWBEYcVPRjvKkgCICpmtPLioetVVe/qDzV30siP6tbKdQHpd9h8
29QaqVogAHYATnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8AAAGOqa44
zQAABAMARzBFAiAdN9lPr+f7SCDEH8f0IMlVChOZwxal+eCA+Q4u0CTbtgIhAK4g
PCAbRWyULxAooW/jWvvSRdsQE3eC4LNmlGNEn8d6MA0GCSqGSIb3DQEBCwUAA4IB
AQBFRcksbjvoZSSun/keQBDzxiIzay9p3YdPAk2mGot8wCnsrgMoBpAw2Idpo2DL
Iq1uXfme1k2kOpJsZZzxj5dLKvU2la/ZqPXqbQHIxY3xhtsBwW/sCPXahbUF0RtO
qGuZF3klFkqJD2kInt681VvikrVpRtH5w4VZIgoQ6wZaz0Y+eqS9ob+SLHjTv+nX
9qUcXRhavhRRz4pB+uJDD8bORwv0a3ryALVHRqZ0CrkF7/6lxvRsKrtoPoeK2ndK
4PiH4oLrzN51g9BgEaJyxG1hzTWDI7NibPgv97GQbGxRzwduSYeXu6XizkbRBZ52
b8UX5QlqnQclO3omEw3VDAP4
-----END CERTIFICATE-----`,
			),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIEPjCCAyagAwIBAgIESlOMKDANBgkqhkiG9w0BAQsFADCBvjELMAkGA1UEBhMC
VVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50
cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAyMDA5IEVudHJ1c3Qs
IEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEyMDAGA1UEAxMpRW50cnVz
dCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzIwHhcNMDkwNzA3MTcy
NTU0WhcNMzAxMjA3MTc1NTU0WjCBvjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVu
dHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwt
dGVybXMxOTA3BgNVBAsTMChjKSAyMDA5IEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0
aG9yaXplZCB1c2Ugb25seTEyMDAGA1UEAxMpRW50cnVzdCBSb290IENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5IC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC6hLZy254Ma+KZ6TABp3bqMriVQRrJ2mFOWHLP/vaCeb9zYQYKpSfYs1/T
RU4cctZOMvJyig/3gxnQaoCAAEUesMfnmr8SVycco2gvCoe9amsOXmXzHHfV1IWN
cCG0szLni6LVhjkCsbjSR87kyUnEO6fe+1R9V77w6G7CebI6C1XiUJgWMhNcL3hW
wcKUs/Ja5CeanyTXxuzQmyWC48zCxEXFjJd6BmsqEZ+pCm5IO2/b1BEZQvePB7/1
U1+cPvQXLOZprE4yTGJ36rfo5bs0vBmLrpxR57d+tVOxMyLlbc9wPBr64ptntoP0
jaWvYkxN4FisZDQSA/i2jZRjJKRxAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRqciZ60B7vfec7aVHUbI2fkBJmqzAN
BgkqhkiG9w0BAQsFAAOCAQEAeZ8dlsa2eT8ijYfThwMEYGprmi5ZiXMRrEPR9RP/
jTkrwPK9T3CMqS/qF8QLVJ7UG5aYMzyorWKiAHarWWluBh1+xLlEjZivEtRh2woZ
Rkfz6/djwUAFQKXSt/S1mja/qYh2iARVBCuch38aNzx+LaUa2NSJXsq9rD1s2G2v
1fN2D807iDginWyTmsQ9v4IbZT+mD12q/OWyFcq1rca8PdCE6OoGcrBNOTJ4vz4R
nAuknZoh8/CbCzB428Hch0P+vGOaysXCHMnHjf87ElgI5rY97HosTvuDls4MPGmH
VHOkc8KT/1EQrBVUAdj8BbGJoX90g5pJ19xOe4pIb4tF9g==
-----END CERTIFICATE-----`),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIFLTCCBBWgAwIBAgIMYaHn0gAAAABR02amMA0GCSqGSIb3DQEBCwUAMIG+MQsw
CQYDVQQGEwJVUzEWMBQGA1UEChMNRW50cnVzdCwgSW5jLjEoMCYGA1UECxMfU2Vl
IHd3dy5lbnRydXN0Lm5ldC9sZWdhbC10ZXJtczE5MDcGA1UECxMwKGMpIDIwMDkg
RW50cnVzdCwgSW5jLiAtIGZvciBhdXRob3JpemVkIHVzZSBvbmx5MTIwMAYDVQQD
EylFbnRydXN0IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMjAeFw0x
NDEyMTUxNTI1MDNaFw0zMDEwMTUxNTU1MDNaMIG6MQswCQYDVQQGEwJVUzEWMBQG
A1UEChMNRW50cnVzdCwgSW5jLjEoMCYGA1UECxMfU2VlIHd3dy5lbnRydXN0Lm5l
dC9sZWdhbC10ZXJtczE5MDcGA1UECxMwKGMpIDIwMTQgRW50cnVzdCwgSW5jLiAt
IGZvciBhdXRob3JpemVkIHVzZSBvbmx5MS4wLAYDVQQDEyVFbnRydXN0IENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5IC0gTDFNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA0IHBOSPCsdHs91fdVSQ2kSAiSPf8ylIKsKs/M7WwhAf23056sPuY
Ij0BrFb7cW2y7rmgD1J3q5iTvjOK64dex6qwymmPQwhqPyK/MzlG1ZTy4kwFItln
gJHxBEoOm3yiydJs/TwJhL39axSagR3nioPvYRZ1R5gTOw2QFpi/iuInMlOZmcP7
lhw192LtjL1JcdJDQ6Gh4yEqI3CodT2ybEYGYW8YZ+QpfrI8wcVfCR5uRE7sIZlY
FUj0VUgqtzS0BeN8SYwAWN46lsw53GEzVc4qLj/RmWLoquY0djGqr3kplnjLgRSv
adr7BLlZg0SqCU+01CwBnZuUMWstoc/B5QIDAQABo4IBKzCCAScwDgYDVR0PAQH/
BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8E
CDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29j
c3AuZW50cnVzdC5uZXQwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL2NybC5lbnRy
dXN0Lm5ldC9nMmNhLmNybDA7BgNVHSAENDAyMDAGBFUdIAAwKDAmBggrBgEFBQcC
ARYaaHR0cDovL3d3dy5lbnRydXN0Lm5ldC9ycGEwHQYDVR0OBBYEFMP30LUqMK2v
DZEhcDlU3byJcMc6MB8GA1UdIwQYMBaAFGpyJnrQHu995ztpUdRsjZ+QEmarMA0G
CSqGSIb3DQEBCwUAA4IBAQC0h8eEIhopwKR47PVPG7SEl2937tTPWa+oQ5YvHVje
pvMVWy7ZQ5xMQrkXFxGttLFBx2YMIoYFp7Qi+8VoaIqIMthx1hGOjlJ+Qgld2dnA
DizvRGsf2yS89byxqsGK5Wbb0CTz34mmi/5e0FC6m3UAyQhKS3Q/WFOv9rihbISY
Jnz8/DVRZZgeO2x28JkPxLkJ1YXYJKd/KsLak0tkuHB8VCnTglTVz6WUwzOeTTRn
4Dh2ZgCN0C/GqwmqcvrOLzWJ/MDtBgO334wlV/H77yiI2YIowAQPlIFpI+CRKMVe
1QzX1CA778n4wI+nQc1XRG5sZ2L+hN/nYNjvv9QiHg3n
-----END CERTIFICATE-----`)
		]

		await verifyCertificateChain(certificateChain, 'usa.experian.com')
	})

	it('should correctly process alternative names', async() => {
		const certs = [
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIMHzCCCwegAwIBAgIQAnCD8P2BEIm80tvV9EiZczANBgkqhkiG9w0BAQsFADBZ
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE
aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjQw
MzEzMDAwMDAwWhcNMjUwMzEyMjM1OTU5WjBqMQswCQYDVQQGEwJVUzETMBEGA1UE
CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMM
QWlyYm5iLCBJbmMuMRcwFQYDVQQDEw53d3cuYWlyYm5iLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABMBcLO0WOO2rpYkCNX1Jpdm1TqOuvQ40eazHGsB+/HaN
UVrU8wSljFWrbhP/HXiVD0TqLGyycOutDFsUZ/UDcsOjggmbMIIJlzAfBgNVHSME
GDAWgBR0hYDAZsffN97PvSk3qgMdvu3NFzAdBgNVHQ4EFgQUvGCtdmbfDLJ9JOSW
NpLFVMlTkR0wggYoBgNVHREEggYfMIIGG4IOd3d3LmFpcmJuYi5jb22CEXd3dy5h
aXJibmIuY29tLnB5gg13d3cuYWlyYm5iLmxhghF3d3cuYWlyYm5iLmNvbS52boIR
d3d3LmFpcmJuYi5jb20uY2+CEXd3dy5haXJibmIuY29tLmJvgg13d3cuYWlyYm5i
Lmlzgg1zay5haXJibmIuY29tggxmci5haXJibmIuY2iCEHd3dy5haXJibmIuY28u
bnqCDXd3dy5haXJibmIuZXOCDXd3dy5haXJibmIuc2WCDXd3dy5haXJibmIuYWWC
EHd3dy5haXJibmIuY28udWuCDXd3dy5haXJibmIuZnKCDXd3dy5haXJibmIuZ3KC
DXd3dy5haXJibmIuYmWCEHd3dy5haXJibmIuY28uaWyCDXd3dy5haXJibmIucnOC
EXd3dy5haXJibmIuY29tLmJ6ghF3d3cuYWlyYm5iLmNvbS5oa4INd3d3LmFpcmJu
Yi5kZYIMZ2EuYWlyYm5iLmllgg13d3cuYWlyYm5iLm1lgg13d3cuYWlyYm5iLmll
gg1oci5haXJibmIuY29tghB3d3cuYWlyYm5iLmNvLmlughF3d3cuYWlyYm5iLmNv
bS5uaYINc3cuYWlyYm5iLmNvbYINd3d3LmFpcmJuYi5qcIIRd3d3LmFpcmJuYi5j
b20ucGiCDXd3dy5haXJibmIubHSCDnd3dy5haXJibmIuY2F0gg1tdC5haXJibmIu
Y29tghF3d3cuYWlyYm5iLmNvbS5raIINd3d3LmFpcmJuYi5hbIINd3d3LmFpcmJu
Yi5jbIIQd3d3LmFpcmJuYi5jby5rcoINd3d3LmFpcmJuYi5pdIINd3d3LmFpcmJu
Yi5ubIIQd3d3LmFpcmJuYi5jby5jcoIRd3d3LmFpcmJuYi5jb20uYXWCDGl0LmFp
cmJuYi5jaIIRd3d3LmFpcmJuYi5jb20uZ3SCEHd3dy5haXJibmIuY28udmWCEXd3
dy5haXJibmIuY29tLmVjgg1oZS5haXJibmIuY29tggxmci5haXJibmIuY2GCDXd3
dy5haXJibmIuYW2CD2EwLm11c2NhY2hlLmNvbYIQd3d3LmFpcmJuYi5jby5pZIIN
d3d3LmFpcmJuYi5wbIINdGguYWlyYm5iLmNvbYINd3d3LmFpcmJuYi5heoIRd3d3
LmFpcmJuYi5jb20ubXSCDXd3dy5haXJibmIuY3qCDXd3dy5haXJibmIubm+CDXp1
LmFpcmJuYi5jb22CEXd3dy5haXJibmIuY29tLnR3gg13d3cuYWlyYm5iLm14gg13
d3cuYWlyYm5iLmNughF3d3cuYWlyYm5iLmNvbS51YYINd3d3LmFpcmJuYi5sdYIR
d3d3LmFpcmJuYi5jb20uc3aCD2VzLWwuYWlyYm5iLmNvbYIRd3d3LmFpcmJuYi5j
b20ucGGCEXd3dy5haXJibmIuY29tLmVlghF3d3cuYWlyYm5iLmNvbS5icoIPaGku
YWlyYm5iLmNvLmlughF3d3cuYWlyYm5iLmNvbS5hcoINd3d3LmFpcmJuYi5ka4IN
c3EuYWlyYm5iLmNvbYIRd3d3LmFpcmJuYi5jb20uaHKCDXd3dy5haXJibmIuaHWC
EXd3dy5haXJibmIuY29tLnRyghF3d3cuYWlyYm5iLmNvbS5wZYINd3d3LmFpcmJu
Yi5zaYINd3d3LmFpcmJuYi5jaIINbWsuYWlyYm5iLmNvbYIRd3d3LmFpcmJuYi5j
b20uc2eCDWFyLmFpcmJuYi5jb22CDGZyLmFpcmJuYi5iZYINd3d3LmFpcmJuYi5m
aYIQd3d3LmFpcmJuYi5jby56YYINd3d3LmFpcmJuYi5wdIIRd3d3LmFpcmJuYi5j
b20ucm+CDXd3dy5haXJibmIuYXSCDWJnLmFpcmJuYi5jb22CEXd3dy5haXJibmIu
Y29tLm15gg1rYS5haXJibmIuY29tghF3d3cuYWlyYm5iLmNvbS5oboINZXMuYWly
Ym5iLmNvbYINd3d3LmFpcmJuYi5iYYINd3d3LmFpcmJuYi5jYYINd3d3LmFpcmJu
Yi5sdjA+BgNVHSAENzA1MDMGBmeBDAECAjApMCcGCCsGAQUFBwIBFhtodHRwOi8v
d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgOIMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjCBnwYDVR0fBIGXMIGUMEigRqBEhkJodHRwOi8v
Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JTQVNIQTI1NjIw
MjBDQTEtMS5jcmwwSKBGoESGQmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdp
Q2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNybDCBhwYIKwYBBQUH
AQEEezB5MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUQYI
KwYBBQUHMAKGRWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEds
b2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNydDAMBgNVHRMBAf8EAjAAMIIB
fgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdwBOdaMnXJoQwzhbbNTfP1LrHfDgjhuN
acCx+mSxYpo53wAAAY45ltWOAAAEAwBIMEYCIQCt2b7pi2Ne92yQh6XegCfiSvP4
jwC6CtcfRUsz3FIRhgIhAOaYj4RITufxjaamcFPGECi+nx+79xEg09/XRk0gme3q
AHYAfVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebgAAAGOOZbViwAABAMA
RzBFAiAeDgFA1MVg1EuOgxnuzVYDOr7radfy+D3agi2sWO50wgIhAPvTrKi+zgXN
a8uUfpT0A5pVKX87h2mkeo/UKDBtES2EAHUA5tIxY0B3jMEQQQbXcbnOwdJA9paE
hvu6hzId/R43jlAAAAGOOZbVtgAABAMARjBEAiA6IFnCjWQEtNVK+4v3+qTZo85y
I/R1xAyGqlSfUA0ehAIgXZNn7VSQ7thny3YEVaQ7HGbsxmnKpcWG/w5K66V+FK8w
DQYJKoZIhvcNAQELBQADggEBABdTjhEELkjGHwCXe7LWD3+aShlNQK1n1uMrYu3q
HrmdSL3YGXtLMqYWOFvqykXHm8Y3DH+2SyeSI/60pXBeTRKc4LVSiu5ai1L3DVyU
wUi/+xPA4bQnuWfNWvtAR0Wxzk71vX6GGLQVj8sDvZCK3ObFCDDdxmMNOL+80Zhx
6GkwWLjyp+OUKTD43+h9YGEopz5UMUplmBEDbRjHdjNhfpBhFPxMSFBUekW0pa9j
Epw8eR9TBJzmwYHhduzyCXXfT1bGcEiHz87aUoOVRTFXOCvxas3yO2ODr6M+XirL
xn4S2Q0dmtc5jnFcmDW6YPP1vD6ThkwXEw9/CmpFCLxdWJY=
-----END CERTIFICATE-----`),
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

		await verifyCertificateChain(certs, 'www.airbnb.co.in')
	})

	it('should correctly process wildcard cert', async() => {
		const certs = [
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIGBzCCBO+gAwIBAgIQUuYJae++wLXq4HrWM334FjANBgkqhkiG9w0BAQsFADBM
MQswCQYDVQQGEwJMVjENMAsGA1UEBxMEUmlnYTERMA8GA1UEChMIR29HZXRTU0wx
GzAZBgNVBAMTEkdvR2V0U1NMIFJTQSBEViBDQTAeFw0yNDAzMTIwMDAwMDBaFw0y
NTAzMTIyMzU5NTlaMBMxETAPBgNVBAMMCCouZ292LnV6MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA0OTudFQdLaUNEwdcysyjCFFqOFml1Nfx2zii6e+g
aSSIzYe4ksITOLDGUxjgvM7nz8quOLv+g7/Oi8RNXDzVZPDpVyALkvOX5cegNmzc
FFuLC+wZQT8l/aL60tTa3M6fDKlPjZowcdHdj3wTLppadRAg91Wt6l58PESSe39y
IjXwmMVSeN2Mn98dD4OE2JMc+ZN0+WSh7DqR4+ysuT6opwoewY+geauztdM/67iV
WHr0CI0gVMDiNxtu6oVmZ7xz/fdG+BuTTQiOuTwiH8BZFZAqKIM0ewJu+c9SMczc
H5CXqEB51JHx+caOGy+pphdrTz17KetrPvOLa+HhJS59CwIDAQABo4IDHDCCAxgw
HwYDVR0jBBgwFoAU+ftQxItnu2dk/oMhpqnOP1WEk5kwHQYDVR0OBBYEFOro2Glm
jK8oJHmiGL7lkjF8V7ySMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBLBgNVHSAERDBCMDYGCysGAQQB
sjEBAgJAMCcwJQYIKwYBBQUHAgEWGWh0dHBzOi8vY3BzLnVzZXJ0cnVzdC5jb20w
CAYGZ4EMAQIBMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwudXNlcnRydXN0
LmNvbS9Hb0dldFNTTFJTQURWQ0EuY3JsMG8GCCsGAQUFBwEBBGMwYTA4BggrBgEF
BQcwAoYsaHR0cDovL2NydC51c2VydHJ1c3QuY29tL0dvR2V0U1NMUlNBRFZDQS5j
cnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wGwYDVR0R
BBQwEoIIKi5nb3YudXqCBmdvdi51ejCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFn
AHYAzxFW7tUufK/zh1vZaS6b6RpxZ0qwF+ysAdJbd87MOwgAAAGOMevWQwAABAMA
RzBFAiEAy5ZV/uS4NGl6OWPxFp/OhQqq+2cLVbf7PPXCsDR3JQgCIAr6Ims+2KtU
65USNdIMNUY/xc3e1HXNZFy62nHY5y2eAHUAouMK5EXvva2bfjjtR2d3U9eCW4SU
1yteGyzEuVCkR+cAAAGOMevV+AAABAMARjBEAiBZh2ddpCUwOLjdaxDR+2NJ2nXU
0ORBB4z42fJExrN9IAIgdikoeRbtyeQvIKsV3+t52XoLsgYAo0UGg6a7kTh95qEA
dgBOdaMnXJoQwzhbbNTfP1LrHfDgjhuNacCx+mSxYpo53wAAAY4x69XpAAAEAwBH
MEUCIQD22LKvy6i7H5NHYQM96dm80RPRPwhagSPQZCBQ0AW6rgIgdqT4hrajZVRH
c4esetu51qv0vnaBTV58eHyY7gNUvmowDQYJKoZIhvcNAQELBQADggEBAFti30mP
4l8j/7cGAaM49q2dN8+YbSzBNHehDEEX/yU2xReuZznuFaQ5tvXGkJbRNg9Q5qjU
LjC9lFxlJYtQWHPLgZ3JGOYUohCt/TmvHEibGpotKKzfBDa2nxz4npn2ExF6ghXS
qcNeKNBrQ6x/UhVTRH9gCYpjKYJPZcmJsTbO8aSigvYATG9cX1HL8Ra3jXsc3/se
WGN39HI+zHva1PeHZ1PXoTxKDadO4CdqW4MUz0Nrn90WTlt8yQWjHy3zcV1uPmqu
ZH8wstCrnzsLqbc1ZIcf74c+9+iFlruFyXu9FP0MCn5yp4xu1Zr5TTAbMLZ/cf/j
SVI8mhu8SfZ2x+4=
-----END CERTIFICATE-----
`),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sI
s9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnG
vDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQ
Ijy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfb
IWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0
tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97E
xwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNV
icQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5
D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJ
WBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ
5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzG
KAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSMEGDAWgBSg
EQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rID
ZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAG
BgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t
L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUA
A4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+cli3vA0p+
rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCRlv79Q2R+
/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHxW/BBC5gA
CiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w52z97GA1F
zZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEUxOipakyA
vGp4z7h/jnZymQyd/teRCBaho1+V
-----END CERTIFICATE-----
`),
			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIF1zCCA7+gAwIBAgIRAJOLsI5imHtPdfmMtqUEXJYwDQYJKoZIhvcNAQEMBQAw
gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK
ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD
VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE4
MDkwNjAwMDAwMFoXDTI4MDkwNTIzNTk1OVowTDELMAkGA1UEBhMCTFYxDTALBgNV
BAcTBFJpZ2ExETAPBgNVBAoTCEdvR2V0U1NMMRswGQYDVQQDExJHb0dldFNTTCBS
U0EgRFYgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfwF4hD6E1
kLglXs1n2fH5vMQukCGyyD4LqLsc3pSzeh8we7njU4TB85BH5YXqcfwiH1Sf78aB
hk1FgXoAZ3EQrF49We8mnTtTPFRnMwEHLJRpY9I/+peKeAZNL0MJG5zM+9gmcSpI
OTI6p7MPela72g0pBQjwcExYLqFFVsnroEPTRRlmfTBTRi9r7rYcXwIct2VUCRmj
jR1GX13op370YjYwgGv/TeYqUWkNiEjWNskFDEfxSc0YfoBwwKdPNfp6t/5+RsFn
lgQKstmFLQbbENsdUEpzWEvZUpDC4qPvRrxEKcF0uLoZhEnxhskwXSTC64BNtc+l
VEk7/g/be8svAgMBAAGjggF1MIIBcTAfBgNVHSMEGDAWgBRTeb9aqitKz1SA4dib
wJ3ysgNmyzAdBgNVHQ4EFgQU+ftQxItnu2dk/oMhpqnOP1WEk5kwDgYDVR0PAQH/
BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMCIGA1UdIAQbMBkwDQYLKwYBBAGyMQECAkAwCAYGZ4EMAQIBMFAG
A1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1
c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB2BggrBgEFBQcBAQRqMGgw
PwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RS
U0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRy
dXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAXXRDKHiA5DOhNKsztwayc8qtlK4q
Vt2XNdlzXn4RyZIsC9+SBi0Xd4vGDhFx6XX4N/fnxlUjdzNN/BYY1gS1xK66Uy3p
rw9qI8X12J4er9lNNhrsvOcjB8CT8FyvFu94j3Bs427uxcSukhYbERBAIN7MpWKl
VWxT3q8GIqiEYVKa/tfWAvnOMDDSKgRwMUtggr/IE77hekQm20p7e1BuJODf1Q7c
FPt7T74m3chg+qu0xheLI6HsUFuOxc7R5SQlkFvaVY5tmswfWpY+rwhyJW+FWNbT
uNXkxR4v5KOQPWrY100/QN68/j17paKuSXNcsr56snuB/Dx+MACLBdsF35HxPadx
78vkfQ37WcVmKZtHrHJQ/QUyjxdG8fezMsh0f+puUln/O+NlsFtipve8qYa9h/K5
yD0oZN93ChWve78XrV4vCpjO75Nk5B8O9CWQqGTHbhkgvjyb9v/B+sYJqB22/NLl
R4RPvbmqDJGeEI+4u6NJ5YiLIVVsX+dyfFP8zUbSsj6J34RyCYKBbQ4L+r7k8Srs
LY51WUFP292wkFDPSDmV7XsUNTDOZoQcBh2Fycf7xFfxeA+6ERx2d8MpPPND7yS2
1dkf+SY5SdpSbAKtYmbqb9q8cZUDEImNWJFUVHBLDOrnYhGwJudE3OBXRTxNhMDm
IXnjEeWrFvAZQhk=
-----END CERTIFICATE-----
`)
		]

		await verifyCertificateChain(certs, 'my.gov.uz')
	})

	it('should verify letsencrypt', async() =>{
		const certs = [loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIDkzCCAxqgAwIBAgISAzLDEn5c9+9n/id222e3VWQqMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
NjAeFw0yNDA3MjgyMjMxNDhaFw0yNDEwMjYyMjMxNDdaMBoxGDAWBgNVBAMTD3lj
b21iaW5hdG9yLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKEb1+xvGsCZ
H58HhAFpFq/JvN7Xgvh6AZStDrvPnXa4wtQhkM3/k8VP5dmyWAfI1ZDL27snXsLV
16kN3Q13NCOjggImMIICIjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFP0GF3YjnnnJ
+1ifgC5tNSxQv0x1MB8GA1UdIwQYMBaAFJMnRpgDqVFojpjWxEJI2yO/WJTSMFUG
CCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL2U2Lm8ubGVuY3Iub3Jn
MCIGCCsGAQUFBzAChhZodHRwOi8vZTYuaS5sZW5jci5vcmcvMC0GA1UdEQQmMCSC
ESoueWNvbWJpbmF0b3IuY29tgg95Y29tYmluYXRvci5jb20wEwYDVR0gBAwwCjAI
BgZngQwBAgEwggEGBgorBgEEAdZ5AgQCBIH3BIH0APIAdwA/F0tP1yJHWJQdZRyE
vg0S7ZA3fx+FauvBvyiF7PhkbgAAAZD7r54uAAAEAwBIMEYCIQCIGW8RI826OCkl
j0qcackUjg8CirkTubJ6Q4rDeVMWdwIhAOE947ROshHUIDTVUzaS6eoWVSGcfhjW
Rga3CEpTT6q7AHcAGZgQcQnw1lIuMIDSnj9ku4NuKMz5D1KO7t/OSj8WtMoAAAGQ
+6+eMQAABAMASDBGAiEAk/j3EQ+PROEj+nPxKYf0DgfjYxtE3CVX7X1ddRuVrnwC
IQCHvOkwO46Y0oOP2IH1vq4L3iGgVGOlQio+c9ynVSuYVTAKBggqhkjOPQQDAwNn
ADBkAjBJariyIphVQLu/OX99WUjPV6UVsG5aetWXgb5Xx7YXYFWPBOAtoQIgi2vn
R5OrcKACMEZhyKhL7pQmyayHS8A/dFNwi6SLTLGMgBR9w32M4d7ifFXtTIy0TXT8
12HecsWdbQ==
-----END CERTIFICATE-----
`),

			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIEVzCCAj+gAwIBAgIRALBXPpFzlydw27SHyzpFKzgwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw
WhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCRTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZ8Z5G
h/ghcWCoJuuj+rnq2h25EqfUJtlRFLFhfHWWvyILOR/VvtEKRqotPEoJhC6+QJVV
6RlAN2Z17TJOdwRJ+HB7wxjnzvdxEP6sdNgA1O1tHHMWMxCcOrLqbGL0vbijgfgw
gfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSTJ0aYA6lRaI6Y1sRCSNsj
v1iU0jAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB
AQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g
BAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu
Y3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAfYt7SiA1sgWGCIpunk46r4AExIRc
MxkKgUhNlrrv1B21hOaXN/5miE+LOTbrcmU/M9yvC6MVY730GNFoL8IhJ8j8vrOL
pMY22OP6baS1k9YMrtDTlwJHoGby04ThTUeBDksS9RiuHvicZqBedQdIF65pZuhp
eDcGBcLiYasQr/EO5gxxtLyTmgsHSOVSBcFOn9lgv7LECPq9i7mfH3mpxgrRKSxH
pOoZ0KXMcB+hHuvlklHntvcI0mMMQ0mhYj6qtMFStkF1RpCG3IPdIwpVCQqu8GV7
s8ubknRzs+3C/Bm19RFOoiPpDkwvyNfvmQ14XkyqqKK5oZ8zhD32kFRQkxa8uZSu
h4aTImFxknu39waBxIRXE4jKxlAmQc4QjFZoq1KmQqQg0J/1JF8RlFvJas1VcjLv
YlvUB2t6npO6oQjB3l+PNf0DpQH7iUx3Wz5AjQCi6L25FjyE06q6BZ/QlmtYdl/8
ZYao4SRqPEs/6cAiF+Qf5zg2UkaWtDphl1LKMuTNLotvsX99HP69V2faNyegodQ0
LyTApr/vT01YPE46vNsDLgK+4cL6TrzC/a4WcmF5SRJ938zrv/duJHLXQIku5v0+
EwOy59Hdm0PT/Er/84dDV0CSjdR/2XuZM3kpysSKLgD1cKiDA+IRguODCxfO9cyY
Ig46v9mFmBvyH04=
-----END CERTIFICATE-----
`),

			loadX509FromPem(`-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
`),
		]

		await verifyCertificateChain(certs, 'bookface.ycombinator.com')
	})

})