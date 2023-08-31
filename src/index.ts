import { randomBytes } from 'crypto'
import EventEmitter from 'events'
import { KeyPair, ProcessPacket, TLSClientOptions, TLSEventEmitter, TLSHandshakeOptions, TLSSessionTicket, X509Certificate } from './types'
import { computeSharedKeys, computeUpdatedTrafficMasterSecret, deriveTrafficKeysForSide, SharedKeyData } from './utils/decryption-utils'
import { concatenateUint8Arrays, toHexStringWithWhitespace } from './utils/generics'
import { CURVES } from './utils/curve'
import LOGGER from './utils/logger'
import { makeQueue } from './utils/make-queue'
import { packClientHello } from './utils/client-hello'
import { AUTH_TAG_BYTE_LENGTH, CONTENT_TYPE_MAP, PACKET_TYPE, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_KEY_TYPE_MAP, SUPPORTED_KEY_TYPES, SUPPORTED_RECORD_TYPE_MAP } from './utils/constants'
import { packFinishMessagePacket, verifyFinishMessage } from './utils/finish-messages'
import { packKeyUpdateRecord } from './utils/key-update'
import { makeMessageProcessor, PacketOptions, packPacketHeader, packWithLength, readWithLength } from './utils/packets'
import { parseTlsAlert } from './utils/parse-alert'
import { parseCertificates, parseServerCertificateVerify, verifyCertificateChain, verifyCertificateSignature } from './utils/parse-certificate'
import { parseServerHello } from './utils/parse-server-hello'
import { getPskFromTicket, parseSessionTicket } from './utils/session-ticket'
import { decryptWrappedRecord, encryptWrappedRecord } from './utils/wrapped-record'

const RECORD_LENGTH_BYTES = 3

type Record = {
	record: Uint8Array
	contentType: number | undefined
	authTag: Uint8Array | undefined
	ciphertext: Uint8Array | undefined
}

type CurveType = keyof typeof CURVES

export function makeTLSClient({
	host,
	verifyServerCertificate,
	rootCAs,
	logger: _logger,
	cipherSuites,
	crypto,
	write
}: TLSClientOptions) {
	verifyServerCertificate = verifyServerCertificate !== false

	const logger = _logger || LOGGER?.child({ })
	const ev = new EventEmitter() as TLSEventEmitter
	const processor = makeMessageProcessor(logger)
	const { enqueue: enqueueServerPacket } = makeQueue()

	let handshakeDone = false
	let ended = false
	const keyPairs = SUPPORTED_KEY_TYPES
		.reduce((acc, curve) => {
			acc[curve] = CURVES[curve].generateKeyPair()
			return acc
		}, {} as { [C in CurveType]: KeyPair })

	let sessionId = new Uint8Array()
	let handshakeMsgs: Uint8Array[] = []
	let cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP | undefined = undefined
	let earlySecret: Uint8Array | undefined = undefined
	let keys: SharedKeyData | undefined = undefined
	let recordSendCount = 0
	let recordRecvCount = 0
	let keyType: keyof typeof SUPPORTED_KEY_TYPE_MAP | undefined = undefined

	let certificates: X509Certificate[] = []
	let handshakePacketStream = new Uint8Array()
	let clientCertificateRequested = false

	const processPacket: ProcessPacket = (type, { header, content, authTag }) => {
		return enqueueServerPacket(async() => {
			if(ended) {
				logger.warn('connection closed, ignoring packet')
				return
			}

			let data = content
			let contentType: number | undefined
			let ciphertext: Uint8Array | undefined
			switch (type) {
			case PACKET_TYPE.HELLO:
				break
			case PACKET_TYPE.WRAPPED_RECORD:
				logger.trace('recv wrapped record')
				const decrypted = decryptWrappedRecord(
					content,
					{
						authTag,
						key: keys!.serverEncKey,
						iv: keys!.serverIv,
						recordHeader: header,
						recordNumber: recordRecvCount,
						cipherSuite: cipherSuite!,
						crypto,
					}
				)
				data = decrypted.plaintext
				// exclude final byte (content type)
				ciphertext = content.slice(0, -1)
				contentType = decrypted.contentType

				logger.debug(
					{
						recordRecvCount,
						contentType: contentType.toString(16),
						length: data.length,
					},
					'decrypted wrapped record'
				)
				recordRecvCount += 1
				break
			case PACKET_TYPE.CHANGE_CIPHER_SPEC:
				// TLS 1.3 doesn't really have a change cipher spec
				// this is just for compatibility with TLS 1.2
				// so we do nothing here, and return
				return
			case PACKET_TYPE.ALERT:
				await handleAlert(content)
				return
			default:
				logger.warn(
					{
						type: type.toString(16),
						chunk: toHexStringWithWhitespace(content)
					},
					'cannot process message'
				)
				return
			}

			try {
				await processRecord({
					record: data,
					contentType,
					authTag,
					ciphertext,
				})
			} catch(err) {
				logger.error({ err }, 'error processing record')
				end(err)
			}
		})
	}

	async function processRecord(
		{
			record,
			contentType,
			authTag,
			ciphertext
		}: Record
	) {
		if(!contentType || contentType === CONTENT_TYPE_MAP.HANDSHAKE) {
			handshakePacketStream = concatenateUint8Arrays([ handshakePacketStream, record ])
			let data = readPacket()
			while(data) {
				const { type, content } = data
				switch (type) {
				case SUPPORTED_RECORD_TYPE_MAP.SERVER_HELLO:
					logger.trace('received server hello')

					const hello = parseServerHello(content)
					if(!hello.supportsPsk && earlySecret) {
						throw new Error('Server does not support PSK')
					}

					cipherSuite = hello.cipherSuite
					keyType = hello.publicKeyType

					const masterKey = CURVES[keyType].calculateSharedKey(
						keyPairs[keyType].privKey,
						hello.publicKey
					)

					keys = computeSharedKeys({
						hellos: handshakeMsgs,
						cipherSuite: hello.cipherSuite,
						secretType: 'hs',
						masterSecret: masterKey,
						earlySecret,
					})

					logger.debug(
						{ cipherSuite, keyType },
						'processed server hello & computed shared keys'
					)
					break
				case SUPPORTED_RECORD_TYPE_MAP.ENCRYPTED_EXTENSIONS:
					logger.debug({ len: content.length }, 'received encrypted extensions')
					break
				case SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE:
					logger.debug({ len: content.length }, 'received certificate')
					const result = parseCertificates(content)
					certificates = result.certificates

					ev.emit('recv-certificates', { certificates })
					break
				case SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE_VERIFY:
					logger.debug({ len: content.length }, 'received certificate verify')
					const signature = parseServerCertificateVerify(content)

					logger.debug({ alg: signature.algorithm }, 'parsed certificate verify')

					if(!certificates.length) {
						throw new Error('No certificates received')
					}

					await verifyCertificateSignature({
						...signature,
						publicKey: certificates[0].getPublicKey(),
						hellos: handshakeMsgs.slice(0, -1),
						cipherSuite: cipherSuite!
					})

					if(verifyServerCertificate) {
						await verifyCertificateChain(certificates, host, rootCAs)
					}

					break
				case SUPPORTED_RECORD_TYPE_MAP.FINISHED:
					await processServerFinish(content)
					break
				case SUPPORTED_RECORD_TYPE_MAP.KEY_UPDATE:
					const newMasterSecret = computeUpdatedTrafficMasterSecret(
						keys!.serverSecret,
						cipherSuite!
					)
					const newKeys = deriveTrafficKeysForSide(newMasterSecret, cipherSuite!)
					keys = {
						...keys!,
						serverSecret: newMasterSecret,
						serverEncKey: newKeys!.encKey,
						serverIv: newKeys!.iv,
					}

					recordRecvCount = 0
					logger.debug('updated server traffic keys')
					break
				case SUPPORTED_RECORD_TYPE_MAP.SESSION_TICKET:
					logger.debug({ len: record.length }, 'received session ticket')
					const ticket = parseSessionTicket(content)
					ev.emit('session-ticket', ticket)
					break
				case SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE_REQUEST:
					logger.debug('received client certificate request')
					clientCertificateRequested = true
					break
				default:
					logger.warn({ type: type.toString(16) }, 'cannot process record')
					break
				}

				data = readPacket()
			}

			function readPacket() {
				if(!handshakePacketStream.length) {
					return
				}

				const type = handshakePacketStream[0]
				const content = readWithLength(handshakePacketStream.slice(1), RECORD_LENGTH_BYTES)
				if(!content) {
					logger.warn('missing bytes from packet')
					return
				}

				const totalLength = 1 + RECORD_LENGTH_BYTES + content.length
				if(!handshakeDone) {
					handshakeMsgs.push(handshakePacketStream.slice(0, totalLength))
				}

				handshakePacketStream = handshakePacketStream.slice(totalLength)

				return { type, content }
			}
		} else if(contentType === CONTENT_TYPE_MAP.APPLICATION_DATA) {
			logger.trace({ len: record.length }, 'received application data')
			ev.emit('data', {
				plaintext: record,
				authTag: authTag!,
				ciphertext: ciphertext!,
			})
		} else if(contentType === CONTENT_TYPE_MAP.ALERT) {
			await handleAlert(record)
		} else {
			logger.warn(
				{ record: record, contentType: contentType.toString(16) },
				'cannot process record'
			)
		}
	}

	async function handleAlert(content: Uint8Array) {
		const { level, description } = parseTlsAlert(content)

		const msg = (
			description === 'HANDSHAKE_FAILURE' || description === 'PROTOCOL_VERSION'
				? 'Unsupported TLS version. Only TLS 1.3 websites with EC certificates are supported'
				: 'received alert'
		)

		logger[level === 'WARNING' ? 'warn' : 'error'](
			{ level, description },
			msg
		)
		if(
			level === 'FATAL'
			|| description === 'CLOSE_NOTIFY'
		) {
			end(
				level === 'FATAL'
					? new Error(`Fatal alert: ${description}`)
					: undefined
			)
		}
	}

	async function sendClientCertificate() {
		if(clientCertificateRequested) {
			const clientZeroCert = concatenateUint8Arrays([
				new Uint8Array([ SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE, 0x00 ]),
				packWithLength(new Uint8Array([0, 0, 0, 0]))])

			logger.trace(
				{ cert: toHexStringWithWhitespace(clientZeroCert) },
				'sending zero certs'
			)
			await writeEncryptedPacket({
				type: 'WRAPPED_RECORD',
				data: clientZeroCert,
				contentType: 'HANDSHAKE'
			})
			handshakeMsgs.push(clientZeroCert)
		}
	}

	async function processServerFinish(serverFinish: Uint8Array) {
		logger.debug('received server finish')

		//derive server keys now to streamline handshake messages handling
		const serverKeys = computeSharedKeys({
			// we only use handshake messages till the server finish
			hellos: handshakeMsgs,
			cipherSuite: cipherSuite!,
			secretType: 'ap',
			masterSecret: keys!.masterSecret,
		})

		// the server hash computation does not include
		// the server finish, so we need to exclude it
		const handshakeMsgsForServerHash = handshakeMsgs.slice(0, -1)

		verifyFinishMessage(serverFinish, {
			secret: keys!.serverSecret,
			handshakeMessages: handshakeMsgsForServerHash,
			cipherSuite: cipherSuite!
		})

		logger.debug('server finish verified')

		// this might add an extra message to handshakeMsgs and affect handshakeHash
		await sendClientCertificate()

		const clientFinish = packFinishMessagePacket({
			secret: keys!.clientSecret,
			handshakeMessages: handshakeMsgs,
			cipherSuite: cipherSuite!
		})

		logger.trace(
			{ finish: toHexStringWithWhitespace(clientFinish) },
			'sending client finish'
		)

		await writeEncryptedPacket({
			type: 'WRAPPED_RECORD',
			data: clientFinish,
			contentType: 'HANDSHAKE'
		})
		// add the client finish to the handshake messages
		handshakeMsgs.push(clientFinish)

		// switch to using the provider keys
		keys = serverKeys

		// also the send/recv counters are reset
		// once we switch to the provider keys
		recordSendCount = 0
		recordRecvCount = 0

		handshakeDone = true
		ev.emit('handshake', undefined)
	}

	async function writeEncryptedPacket(opts: PacketOptions & { contentType: keyof typeof CONTENT_TYPE_MAP }) {
		logger.trace(
			{ ...opts, data: toHexStringWithWhitespace(opts.data) },
			'writing enc packet'
		)
		// total length = data len + 1 byte for record type + auth tag len
		const dataLen = opts.data.length + 1 + AUTH_TAG_BYTE_LENGTH
		const header = packPacketHeader(dataLen, opts)

		const { ciphertext, authTag } = encryptWrappedRecord(
			{ plaintext: opts.data, contentType: opts.contentType },
			{
				key: keys!.clientEncKey,
				iv: keys!.clientIv,
				recordHeader: header,
				recordNumber: recordSendCount,
				cipherSuite: cipherSuite!,
				crypto
			}
		)

		recordSendCount += 1

		await write({ header, content: ciphertext, authTag })
	}

	async function writePacket(opts: PacketOptions) {
		logger.trace(
			{ ...opts, data: toHexStringWithWhitespace(opts.data) },
			'writing packet'
		)
		const header = packPacketHeader(opts.data.length, opts)
		await write({ header, content: opts.data })
	}

	async function end(error?: Error) {
		await enqueueServerPacket(() => { })
		handshakeDone = false
		handshakeMsgs = []
		keys = undefined
		recordSendCount = 0
		recordRecvCount = 0
		earlySecret = undefined
		processor.reset()

		ended = true
		ev.emit('end', { error })
	}

	return {
		ev,
		getMetadata() {
			return {
				cipherSuite,
				keyType,
			}
		},
		hasEnded() {
			return ended
		},
		getKeyPair() {
			if(!keyType) {
				throw new Error('handshake not done yet')
			}

			return keyPairs[keyType]
		},
		getKeys() {
			if(!keys) {
				return undefined
			}

			return { ...keys, recordSendCount, recordRecvCount }
		},
		getSessionId() {
			return sessionId
		},
		isHandshakeDone() {
			return handshakeDone
		},
		getPskFromTicket(ticket: TLSSessionTicket) {
			return getPskFromTicket(ticket, {
				masterKey: keys!.masterSecret,
				hellos: handshakeMsgs,
				cipherSuite: cipherSuite!,
			})
		},
		async startHandshake(opts?: TLSHandshakeOptions) {
			if(handshakeDone) {
				throw new Error('Handshake already done')
			}

			sessionId = randomBytes(32)
			ended = false

			const clientHello = packClientHello({
				host,
				keysToShare: Object.entries(keyPairs)
					.map(([keyType, keyPair]) => ({
						type: keyType as CurveType,
						key: keyPair.pubKey
					})),
				random: opts?.random || randomBytes(32),
				sessionId,
				psk: opts?.psk,
				cipherSuites
			})
			handshakeMsgs.push(clientHello)

			if(opts?.psk) {
				earlySecret = opts.psk.earlySecret
			}

			await writePacket({
				type: 'HELLO',
				data: clientHello,
			})
		},
		handleRawData(data: Uint8Array) {
			processor.onData(data, processPacket)
		},
		async updateTrafficKeys(requestUpdateFromServer = false) {
			const packet = packKeyUpdateRecord(
				requestUpdateFromServer
					? 'UPDATE_REQUESTED'
					: 'UPDATE_NOT_REQUESTED'
			)
			await writeEncryptedPacket({
				data: packet,
				type: 'WRAPPED_RECORD',
				contentType: 'HANDSHAKE'
			})

			const newMasterSecret = computeUpdatedTrafficMasterSecret(
				keys!.clientSecret,
				cipherSuite!
			)
			const newKeys = deriveTrafficKeysForSide(newMasterSecret, cipherSuite!)
			keys = {
				...keys!,
				clientSecret: newMasterSecret,
				clientEncKey: newKeys!.encKey,
				clientIv: newKeys!.iv,
			}

			recordSendCount = 0

			logger.info('updated client traffic keys')
		},
		processPacket,
		write(data: Uint8Array) {
			if(!handshakeDone) {
				throw new Error('Handshake not done')
			}

			return writeEncryptedPacket({
				type: 'WRAPPED_RECORD',
				data,
				contentType: 'APPLICATION_DATA'
			})
		},
		end,
	}
}