import Chance from 'chance'
import { Socket } from 'net'
import { TLSClientOptions, TLSPresharedKey } from '../types'
import { crypto, makeTLSClient, strToUint8Array, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_NAMED_CURVE_MAP } from '../'
import { createMockTLSServer } from './mock-tls-server'
import { delay, logger } from './utils'

const chance = new Chance()

const TLS_NAMED_CURVES = Object.keys(SUPPORTED_NAMED_CURVE_MAP) as (keyof typeof SUPPORTED_NAMED_CURVE_MAP)[]
const TLS12_CIPHER_SUITES: (keyof typeof SUPPORTED_CIPHER_SUITE_MAP)[] = [
	// our test cert is RSA -- so the ECDSA tests won't work
	// 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
	// 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
	// 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
	'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
	'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
	'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
]

const DATA_POINTS = [
	strToUint8Array('hi'),
	strToUint8Array('hello world'),
	crypto.randomBytes(100),
]

describe('TLS 1.2 Tests', () => {

	const port = chance.integer({ min: 10000, max: 20000 })
	const srv = createMockTLSServer(port)

	beforeAll(async() => {
		await delay(200)
	})

	afterAll(() => {
		srv.server.close()
	})

	it.each(TLS_NAMED_CURVES)('[%s] should do handshake with the server', async(curve) => {
		const { tls, socket } = connectTLS({ namedCurves: [curve] })

		while(!tls.isHandshakeDone()) {
			await delay(100)

			if(socket.readableEnded) {
				throw new Error('unexpectedly terminated')
			}
		}

		socket.end()

		expect(tls.getSessionId()).toBeDefined()
		expect(tls.getKeys()?.clientEncKey).toBeDefined()

		await tls.end()
	})

	describe.each(TLS12_CIPHER_SUITES)('[%s] Data Exchange', (cipher) => {

		const onRecvData = jest.fn()
		let conn: ReturnType<typeof connectTLS>

		beforeAll(async() => {
			conn = connectTLS({
				onRecvData,
				cipherSuites: [cipher]
			})
			while(!conn.tls.isHandshakeDone()) {
				await delay(100)
			}
		})

		afterAll(async() => {
			conn.socket.end()
			await conn.tls.end()
		})

		for(const data of DATA_POINTS) {
			it(`should send & recv ${data.length} bytes from the server`, async() => {
				const { tls } = conn
				const recvDataPromise = new Promise<Uint8Array>(resolve => {
					onRecvData.mockImplementationOnce((plaintext) => {
						resolve(plaintext)
					})
				})

				await tls.write(data)

				const recvData = await recvDataPromise
				expect(recvData).toEqual(data)
			})
		}
	})

	function connectTLS(
		opts?: Partial<TLSClientOptions>,
		psk?: TLSPresharedKey
	) {
		const socket = new Socket()
		const host = 'localhost'
		socket.connect({ host, port })

		const tls = makeTLSClient({
			host,
			verifyServerCertificate: false,
			supportedProtocolVersions: ['TLS1_2'],
			logger,
			async write({ header, content, authTag }) {
				socket.write(header)
				socket.write(content)
				if(authTag) {
					socket.write(authTag)
				}
			},
			...opts,
		})

		socket.on('data', tls.handleReceivedBytes)

		socket.on('connect', () => tls.startHandshake({ psk }))

		return { tls, socket }
	}
})