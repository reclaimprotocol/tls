import { packClientHello } from './utils/client-hello'
import { AUTH_TAG_BYTE_LENGTH, CONTENT_TYPE_MAP, PACKET_TYPE, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_NAMED_CURVES, SUPPORTED_RECORD_TYPE_MAP } from './utils/constants'
import { computeSharedKeys, computeUpdatedTrafficMasterSecret, deriveTrafficKeysForSide, SharedKeyData } from './utils/decryption-utils'
import { packFinishMessagePacket, verifyFinishMessage } from './utils/finish-messages'
import { concatenateUint8Arrays, toHexStringWithWhitespace } from './utils/generics'
import { packKeyUpdateRecord } from './utils/key-update'
import { logger as LOGGER } from './utils/logger'
import { makeQueue } from './utils/make-queue'
import { makeMessageProcessor, PacketOptions, packPacketHeader, packWithLength, readWithLength } from './utils/packets'
import { parseTlsAlert } from './utils/parse-alert'
import { parseCertificates, parseServerCertificateVerify, verifyCertificateChain, verifyCertificateSignature } from './utils/parse-certificate'
import { parseServerHello } from './utils/parse-server-hello'
import { getPskFromTicket, parseSessionTicket } from './utils/session-ticket'
import { decryptWrappedRecord, encryptWrappedRecord } from './utils/wrapped-record'
import { crypto } from './crypto'
import { KeyPair, ProcessPacket, TLSClientOptions, TLSHandshakeOptions, TLSSessionTicket, X509Certificate } from './types'

const RECORD_LENGTH_BYTES = 3

type Record = {
	record: Uint8Array
	contentType: number | undefined
	authTag: Uint8Array | undefined
	ciphertext: Uint8Array | undefined
}

export function makeTLSClient({
	host,
	verifyServerCertificate,
	rootCAs,
	logger: _logger,
	cipherSuites,
	namedCurves,
	write,
	onRecvData,
	onSessionTicket,
	onTlsEnd,
	onHandshake,
	onRecvCertificates
}: TLSClientOptions) {
	verifyServerCertificate = verifyServerCertificate !== false
	namedCurves = namedCurves || SUPPORTED_NAMED_CURVES

	const logger = _logger || LOGGER
	const processor = makeMessageProcessor(logger)
	const { enqueue: enqueueServerPacket } = makeQueue()

	const keyPairs: { [C in keyof typeof SUPPORTED_NAMED_CURVE_MAP]?: KeyPair } = {}
	let handshakeDone = false
	let ended = false
	let sessionId = new Uint8Array()
	let handshakeMsgs: Uint8Array[] = []
	let cipherSuite: keyof typeof SUPPORTED_CIPHER_SUITE_MAP | undefined = undefined
	let earlySecret: Uint8Array | undefined = undefined
	let keys: SharedKeyData | undefined = undefined
	let recordSendCount = 0
	let recordRecvCount = 0
	let keyType: keyof typeof SUPPORTED_NAMED_CURVE_MAP | undefined = undefined

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
				const decrypted = await decryptWrappedRecord(
					content,
					{
						authTag,
						key: keys!.serverEncKey,
						iv: keys!.serverIv,
						recordHeader: header,
						recordNumber: recordRecvCount,
						cipherSuite: cipherSuite!,
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

					const hello = await parseServerHello(content)
					if(!hello.supportsPsk && earlySecret) {
						throw new Error('Server does not support PSK')
					}

					cipherSuite = hello.cipherSuite
					keyType = hello.publicKeyType

					const {
						keyPair,
						algorithm
					} = await getKeyPair(keyType)
					const masterSecret = await crypto.calculateSharedSecret(
						algorithm,
						keyPair.privKey,
						hello.publicKey
					)

					keys = await computeSharedKeys({
						hellos: handshakeMsgs,
						cipherSuite: hello.cipherSuite,
						secretType: 'hs',
						masterSecret,
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

					onRecvCertificates?.({ certificates })
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
					const newMasterSecret = await computeUpdatedTrafficMasterSecret(
						keys!.serverSecret,
						cipherSuite!
					)
					const newKeys = await deriveTrafficKeysForSide(newMasterSecret, cipherSuite!)
					keys = {
						...keys!,
						serverSecret: newMasterSecret,
						serverEncKey: newKeys.encKey,
						serverIv: newKeys.iv,
					}

					recordRecvCount = 0
					logger.debug('updated server traffic keys')
					break
				case SUPPORTED_RECORD_TYPE_MAP.SESSION_TICKET:
					logger.debug({ len: record.length }, 'received session ticket')
					const ticket = parseSessionTicket(content)
					onSessionTicket?.(ticket)
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
			onRecvData?.(record, { authTag: authTag!, ciphertext: ciphertext!, })
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
		const serverKeys = await computeSharedKeys({
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

		const clientFinish = await packFinishMessagePacket({
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
		onHandshake?.()
	}

	async function writeEncryptedPacket(opts: PacketOptions & { contentType: keyof typeof CONTENT_TYPE_MAP }) {
		logger.trace(
			{ ...opts, data: toHexStringWithWhitespace(opts.data) },
			'writing enc packet'
		)
		// total length = data len + 1 byte for record type + auth tag len
		const dataLen = opts.data.length + 1 + AUTH_TAG_BYTE_LENGTH
		const header = packPacketHeader(dataLen, opts)

		const { ciphertext, authTag } = await encryptWrappedRecord(
			{ plaintext: opts.data, contentType: opts.contentType },
			{
				key: keys!.clientEncKey,
				iv: keys!.clientIv,
				recordHeader: header,
				recordNumber: recordSendCount,
				cipherSuite: cipherSuite!,
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
		onTlsEnd?.(error)
	}

	async function getKeyPair(keyType: keyof typeof SUPPORTED_NAMED_CURVE_MAP) {
		const algorithm = SUPPORTED_NAMED_CURVE_MAP[keyType].algorithm
		if(!keyPairs[keyType]) {
			keyPairs[keyType] = await crypto.generateKeyPair(algorithm)
		}

		return {
			algorithm,
			keyPair: keyPairs[keyType]!
		}
	}

	return {
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
		/**
		 * Get the current traffic keys
		 */
		getKeys() {
			if(!keys) {
				return undefined
			}

			return { ...keys, recordSendCount, recordRecvCount }
		},
		/**
		 * Session ID used to connect to the server
		 */
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
		/**
		 * Start the handshake with the server
		 */
		async startHandshake(opts?: TLSHandshakeOptions) {
			if(handshakeDone) {
				throw new Error('Handshake already done')
			}

			sessionId = crypto.randomBytes(32)
			ended = false

			const clientHello = await packClientHello({
				host,
				keysToShare: await Promise.all(
					namedCurves!
						.map(async(keyType) => {
							const { keyPair } = await getKeyPair(keyType)
							return {
								type: keyType,
								key: keyPair.pubKey,
							}
						})
				),
				random: opts?.random || crypto.randomBytes(32),
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
		/**
		 * Handle bytes received from the server.
		 * Could be a complete or partial TLS packet
		 */
		handleReceivedBytes(data: Uint8Array) {
			processor.onData(data, processPacket)
		},
		/**
		 * Handle a complete TLS packet received
		 * from the server
		 */
		handleReceivedPacket: processPacket,
		/**
		 * Utilise the KeyUpdate handshake message to update
		 * the traffic keys. Available only in TLS 1.3
		 * @param requestUpdateFromServer should the server be requested to
		 * update its keys as well
		 */
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

			const newMasterSecret = await computeUpdatedTrafficMasterSecret(
				keys!.clientSecret,
				cipherSuite!
			)
			const newKeys = await deriveTrafficKeysForSide(newMasterSecret, cipherSuite!)
			keys = {
				...keys!,
				clientSecret: newMasterSecret,
				clientEncKey: newKeys.encKey,
				clientIv: newKeys.iv,
			}

			recordSendCount = 0

			logger.info('updated client traffic keys')
		},
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