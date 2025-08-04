import { crypto } from './crypto/index.ts'
import type { CipherSuite, Key, KeyPair, ProcessPacket, TLSClientOptions, TLSHandshakeOptions, TLSKeyType, TLSPacket, TLSPacketContext, TLSProtocolVersion, TLSSessionTicket, X509Certificate } from './types/index.ts'
import { packClientHello } from './utils/client-hello.ts'
import { CONTENT_TYPE_MAP, MAX_ENC_PACKET_SIZE, PACKET_TYPE, SUPPORTED_CIPHER_SUITE_MAP, SUPPORTED_NAMED_CURVE_MAP, SUPPORTED_NAMED_CURVES, SUPPORTED_RECORD_TYPE_MAP } from './utils/constants.ts'
import type { SharedKeyData } from './utils/decryption-utils.ts'
import { computeSharedKeys, computeSharedKeysTls12, computeUpdatedTrafficMasterSecret, deriveTrafficKeysForSide } from './utils/decryption-utils.ts'
import { generateFinishTls12, packClientFinishTls12, packFinishMessagePacket, verifyFinishMessage } from './utils/finish-messages.ts'
import { areUint8ArraysEqual, chunkUint8Array, concatenateUint8Arrays, toHexStringWithWhitespace } from './utils/generics.ts'
import { createRsaPreMasterSecret, packClientCurveKeyShare, packClientRsaKeyShare, processServerKeyShare } from './utils/key-share.ts'
import { packKeyUpdateRecord } from './utils/key-update.ts'
import { logger as LOGGER } from './utils/logger.ts'
import { makeQueue } from './utils/make-queue.ts'
import type { PacketOptions } from './utils/packets.ts'
import { makeMessageProcessor, packPacketHeader, packWithLength, readWithLength } from './utils/packets.ts'
import { parseTlsAlert } from './utils/parse-alert.ts'
import { getSignatureDataTls12, getSignatureDataTls13, parseCertificates, parseServerCertificateVerify, verifyCertificateChain, verifyCertificateSignature } from './utils/parse-certificate.ts'
import { parseServerExtensions } from './utils/parse-extensions.ts'
import { parseServerHello } from './utils/parse-server-hello.ts'
import { getPskFromTicket, parseSessionTicket } from './utils/session-ticket.ts'
import { decryptWrappedRecord, encryptWrappedRecord } from './utils/wrapped-record.ts'

const RECORD_LENGTH_BYTES = 3

export function makeTLSClient({
	host,
	verifyServerCertificate = true,
	rootCAs,
	logger: _logger,
	cipherSuites,
	namedCurves = SUPPORTED_NAMED_CURVES,
	supportedProtocolVersions,
	signatureAlgorithms,
	applicationLayerProtocols,
	write,
	onRead,
	onApplicationData,
	onSessionTicket,
	onTlsEnd,
	onHandshake,
	onRecvCertificates
}: TLSClientOptions) {
	const logger = _logger || LOGGER
	const processor = makeMessageProcessor(logger)
	const { enqueue: enqueueServerPacket } = makeQueue()

	const keyPairs: { [C in TLSKeyType]?: KeyPair } = {}
	let handshakeDone = false
	let ended = false
	let sessionId: Uint8Array = new Uint8Array()
	let handshakeMsgs: Uint8Array[] = []
	let cipherSuite: CipherSuite | undefined = undefined
	let earlySecret: Uint8Array | undefined = undefined
	let keys: SharedKeyData | undefined = undefined
	let recordSendCount = 0
	let recordRecvCount = 0
	let keyType: TLSKeyType | undefined = undefined
	let connTlsVersion: TLSProtocolVersion | undefined = undefined
	let clientRandom: Uint8Array | undefined = undefined
	let serverRandom: Uint8Array | undefined = undefined
	let cipherSpecChanged = false
	let selectedAlpn: string | undefined

	let certificates: X509Certificate[] | undefined
	let handshakePacketStream: Uint8Array = new Uint8Array()
	let clientCertificateRequested = false
	let certificatesVerified = false

	const processPacketUnsafe: ProcessPacket = async(type, { header, content }) => {
		if(ended) {
			logger.warn('connection closed, ignoring packet')
			return
		}

		let contentType: keyof typeof CONTENT_TYPE_MAP | undefined
		let ctx: TLSPacketContext = { type: 'plaintext' }
		// if the cipher spec has changed,
		// the data will be encrypted, so
		// we need to decrypt the packet
		if(cipherSpecChanged || type === PACKET_TYPE.WRAPPED_RECORD) {
			logger.trace('recv wrapped record')
			const macKey = 'serverMacKey' in keys!
				? keys.serverMacKey
				: undefined
			const decrypted = await decryptWrappedRecord(
				content,
				{
					key: keys!.serverEncKey,
					iv: keys!.serverIv,
					recordHeader: header,
					recordNumber: recordRecvCount,
					cipherSuite: cipherSuite!,
					version: connTlsVersion!,
					macKey,
				}
			)

			if(connTlsVersion === 'TLS1_3') {
				// TLS 1.3 has an extra byte suffixed
				// this denotes the content type of the
				// packet
				const contentTypeNum = decrypted
					.plaintext[decrypted.plaintext.length - 1]
				contentType = Object.entries(CONTENT_TYPE_MAP)
					.find(([, val]) => val === contentTypeNum)?.[0] as keyof typeof CONTENT_TYPE_MAP
			}

			ctx = {
				type: 'ciphertext',
				encKey: keys!.serverEncKey,
				fixedIv: keys!.serverIv,
				iv: decrypted.iv,
				recordNumber: recordRecvCount,
				macKey,
				ciphertext: content,
				plaintext: decrypted.plaintext,
				contentType,
			}

			content = decrypted.plaintext
			if(contentType) {
				content = content.slice(0, -1)
			}

			logger.trace(
				{
					recordRecvCount,
					contentType,
					length: content.length,
				},
				'decrypted wrapped record'
			)
			recordRecvCount += 1
		}

		onRead?.({ content, header }, ctx)

		if(
			type === PACKET_TYPE.WRAPPED_RECORD
			|| type === PACKET_TYPE.HELLO
		) {
			// do nothing -- pass through
		} else if(type === PACKET_TYPE.CHANGE_CIPHER_SPEC) {
			logger.debug('received change cipher spec')
			cipherSpecChanged = true
			return
		} else if(type === PACKET_TYPE.ALERT) {
			await handleAlert(content)
			return
		} else {
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
			await processRecord(
				{
					content,
					contentType: contentType
						? CONTENT_TYPE_MAP[contentType]
						: undefined,
					header,
				},
			)
		} catch(err) {
			logger.error({ err }, 'error processing record')
			end(err)
		}
	}

	const processPacket: ProcessPacket = (...args) => (
		enqueueServerPacket(processPacketUnsafe, ...args)
	)

	async function processRecord(
		{
			content: record,
			contentType,
			header,
		}: TLSPacket & { contentType?: number },
	) {
		contentType ??= header[0]
		if(contentType === CONTENT_TYPE_MAP.HANDSHAKE) {
			handshakePacketStream = concatenateUint8Arrays([ handshakePacketStream, record ])
			let data: ReturnType<typeof readPacket>
			while(data = readPacket()) {
				const { type, content } = data
				switch (type) {
				case SUPPORTED_RECORD_TYPE_MAP.SERVER_HELLO:
					logger.trace('received server hello')

					const hello = await parseServerHello(content)
					if(!hello.supportsPsk && earlySecret) {
						throw new Error('Server does not support PSK')
					}

					cipherSuite = hello.cipherSuite
					connTlsVersion = hello.serverTlsVersion
					serverRandom = hello.serverRandom
					setAlpn(hello.extensions?.ALPN)

					const cipherSuiteData = SUPPORTED_CIPHER_SUITE_MAP[cipherSuite]

					logger.debug(
						{ cipherSuite, connTlsVersion, selectedAlpn },
						'processed server hello'
					)

					if(hello.publicKeyType && hello.publicKey) {
						await processServerPubKey({
							publicKeyType: hello.publicKeyType,
							publicKey: hello.publicKey
						})
					} else if(
						'isRsaEcdh' in cipherSuiteData && cipherSuiteData.isRsaEcdh
					) {
						keyType = 'RSA'
					}

					break
				case SUPPORTED_RECORD_TYPE_MAP.ENCRYPTED_EXTENSIONS:
					const extData = parseServerExtensions(content)
					logger.debug({
						len: content.length,
						extData
					}, 'received encrypted extensions')
					setAlpn(extData?.ALPN)
					break
				case SUPPORTED_RECORD_TYPE_MAP.HELLO_RETRY_REQUEST:
					throw new Error('Hello retry not supported. Please re-establish connection')
				case SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE:
					logger.trace({ len: content.length }, 'received certificate')
					const result = parseCertificates(content, { version: connTlsVersion! })
					certificates = result.certificates

					logger.debug({ len: certificates.length }, 'parsed certificates')

					if(verifyServerCertificate) {
						await verifyCertificateChain(certificates, host, rootCAs)
						logger.debug('verified certificate chain')

						certificatesVerified = true
					}

					onRecvCertificates?.({ certificates })
					break
				case SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE_VERIFY:
					logger.debug({ len: content.length }, 'received certificate verify')
					const signature = parseServerCertificateVerify(content)

					logger.debug({ alg: signature.algorithm }, 'parsed certificate verify')

					if(!certificates?.length) {
						throw new Error('No certificates received')
					}

					const signatureData = await getSignatureDataTls13(
						handshakeMsgs.slice(0, -1),
						cipherSuite!
					)
					await verifyCertificateSignature({
						...signature,
						publicKey: certificates[0].getPublicKey(),
						signatureData,
					})

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
					if(connTlsVersion === 'TLS1_3') {
						logger.debug({ len: record.length }, 'received session ticket')
						const ticket = parseSessionTicket(content)
						onSessionTicket?.(ticket)
					} else {
						logger.warn('ignoring received session ticket in TLS 1.2')
					}

					break
				case SUPPORTED_RECORD_TYPE_MAP.CERTIFICATE_REQUEST:
					logger.debug('received client certificate request')
					clientCertificateRequested = true
					break
				case SUPPORTED_RECORD_TYPE_MAP.SERVER_KEY_SHARE:
					logger.trace('received server key share')
					if(!certificates?.length) {
						throw new Error('No certificates received')
					}

					// extract pub key & signature of pub key with cert
					const keyShare = await processServerKeyShare(content)
					logger.debug(
						{
							publicKeyType: keyShare.publicKeyType,
							signatureAlgorithm: keyShare.signatureAlgorithm,
						},
						'got server key share'
					)
					// compute signature data
					const signatureData12 = await getSignatureDataTls12(
						{
							clientRandom: clientRandom!,
							serverRandom: serverRandom!,
							curveType: keyShare.publicKeyType,
							publicKey: keyShare.publicKey,
						},
					)
					// verify signature
					await verifyCertificateSignature({
						signature: keyShare.signatureBytes,
						algorithm: keyShare.signatureAlgorithm,
						publicKey: certificates[0].getPublicKey(),
						signatureData: signatureData12,
					})

					logger.debug('verified server key share signature')

					if(verifyServerCertificate) {
						await verifyCertificateChain(certificates, host, rootCAs)
						logger.debug('verified certificate chain')

						certificatesVerified = true
					}

					// compute shared keys
					await processServerPubKey(keyShare)

					break
				case SUPPORTED_RECORD_TYPE_MAP.SERVER_HELLO_DONE:
					logger.debug('server hello done')
					if(!keyType) {
						// need to execute client key share
						throw new Error('Key exchange without key-type not supported')
					}

					let clientKeyShare: Uint8Array
					if(keyType === 'RSA') {
						if(keys) {
							throw new Error('Keys already computed, despite RSA key type')
						}

						const {
							preMasterSecret, encrypted
						} = await createRsaPreMasterSecret(
							certificates![0],
							connTlsVersion!
						)
						clientKeyShare = await packClientRsaKeyShare(encrypted)
						keys = await computeSharedKeysTls12({
							preMasterSecret: preMasterSecret,
							clientRandom: clientRandom!,
							serverRandom: serverRandom!,
							cipherSuite: cipherSuite!,
						})
					} else {
						clientKeyShare
							= await packClientCurveKeyShare(keyPairs[keyType]!.pubKey)
					}

					await writePacket({ type: 'HELLO', data: clientKeyShare })
					handshakeMsgs.push(clientKeyShare)

					await writeChangeCipherSpec()

					const finishMsg = await packClientFinishTls12({
						secret: keys!.masterSecret,
						handshakeMessages: handshakeMsgs,
						cipherSuite: cipherSuite!,
					})
					await writeEncryptedPacket({ data: finishMsg, type: 'HELLO' })

					handshakeMsgs.push(finishMsg)

					break
				default:
					logger.warn({ type: type.toString(16) }, 'cannot process record')
					break
				}
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
			onApplicationData?.(record)
		} else if(contentType === CONTENT_TYPE_MAP.ALERT) {
			await handleAlert(record)
		} else {
			logger.warn(
				{ record: record, contentType: contentType?.toString(16) },
				'cannot process record'
			)
		}
	}

	function setAlpn(alpn: string | undefined) {
		selectedAlpn = alpn || applicationLayerProtocols?.[0]
		if(selectedAlpn && !applicationLayerProtocols?.includes(selectedAlpn)) {
			throw new Error(`Server selected unsupported ALPN: "${selectedAlpn}"`)
		}
	}

	async function handleAlert(content: Uint8Array) {
		if(ended) {
			logger.warn('connection closed, ignoring alert')
			return
		}

		const { level, description } = parseTlsAlert(content)

		const msg = (
			description === 'HANDSHAKE_FAILURE' || description === 'PROTOCOL_VERSION'
				? 'Unsupported TLS version'
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

		if(!certificatesVerified && verifyServerCertificate) {
			throw new Error(
				'Finish received before certificate verification'
			)
		}

		if(connTlsVersion === 'TLS1_2') {
			await processServerFinishTls12(serverFinish)
		} else {
			await processServerFinishTls13(serverFinish)
		}

		handshakeDone = true
		onHandshake?.()
	}

	async function processServerFinishTls12(serverFinish: Uint8Array) {
		const genServerFinish = await generateFinishTls12('server', {
			handshakeMessages: handshakeMsgs.slice(0, -1),
			secret: keys!.masterSecret,
			cipherSuite: cipherSuite!,
		})
		if(!areUint8ArraysEqual(genServerFinish, serverFinish)) {
			throw new Error('Server finish does not match')
		}
	}

	async function processServerFinishTls13(serverFinish: Uint8Array) {

		// derive server keys now to streamline handshake messages handling
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

		await verifyFinishMessage(serverFinish, {
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
	}

	async function processServerPubKey(data: {
		publicKeyType: keyof typeof SUPPORTED_NAMED_CURVE_MAP
		publicKey: Key
	}) {
		keyType = data.publicKeyType
		const {
			keyPair,
			algorithm
		} = await getKeyPair(data.publicKeyType)
		const sharedSecret = await crypto.calculateSharedSecret(
			algorithm,
			keyPair.privKey,
			data.publicKey
		)

		if(connTlsVersion === 'TLS1_2') {
			keys = await computeSharedKeysTls12({
				preMasterSecret: sharedSecret,
				clientRandom: clientRandom!,
				serverRandom: serverRandom!,
				cipherSuite: cipherSuite!,
			})
		} else {
			keys = await computeSharedKeys({
				hellos: handshakeMsgs,
				cipherSuite: cipherSuite!,
				secretType: 'hs',
				masterSecret: sharedSecret,
				earlySecret,
			})
		}

		logger.debug({ keyType }, 'computed shared keys')
	}

	async function writeChangeCipherSpec() {
		logger.debug('sending change cipher spec')
		const changeCipherSpecData = new Uint8Array([ 1 ])
		await writePacket({
			type: 'CHANGE_CIPHER_SPEC',
			data: changeCipherSpecData
		})
	}

	async function writeEncryptedPacket(
		opts: PacketOptions & { contentType?: keyof typeof CONTENT_TYPE_MAP }
	) {
		logger.trace(
			{ ...opts, data: toHexStringWithWhitespace(opts.data) },
			'writing enc packet'
		)

		const macKey = 'clientMacKey' in keys!
			? keys.clientMacKey
			: undefined

		let plaintext = opts.data
		if(
			connTlsVersion === 'TLS1_3'
			&& typeof opts.contentType !== 'undefined'
		) {
			plaintext = concatenateUint8Arrays([
				plaintext,
				new Uint8Array([ CONTENT_TYPE_MAP[opts.contentType] ])
			])
		}

		const { ciphertext, iv } = await encryptWrappedRecord(
			plaintext,
			{
				key: keys!.clientEncKey,
				iv: keys!.clientIv,
				recordNumber: recordSendCount,
				cipherSuite: cipherSuite!,
				macKey,
				recordHeaderOpts: {
					type: opts.type,
					version: opts.version
				},
				version: connTlsVersion!,
			}
		)

		const header = packPacketHeader(ciphertext.length, opts)

		await write(
			{ header, content: ciphertext },
			{
				type: 'ciphertext',
				encKey: keys!.clientEncKey,
				fixedIv: keys!.clientIv,
				iv,
				recordNumber: recordSendCount,
				macKey,
				ciphertext,
				plaintext,
				contentType: opts.contentType,
			}
		)

		recordSendCount += 1
	}

	async function writePacket(opts: PacketOptions) {
		logger.trace(
			{ ...opts, data: toHexStringWithWhitespace(opts.data) },
			'writing packet'
		)
		const header = packPacketHeader(opts.data.length, opts)
		await write(
			{ header, content: opts.data },
			{ type: 'plaintext' }
		)
	}

	async function end(error?: Error) {
		await enqueueServerPacket(() => { })

		ended = true
		handshakeDone = false
		handshakeMsgs = []
		keys = undefined
		recordSendCount = 0
		recordRecvCount = 0
		earlySecret = undefined
		cipherSuite = undefined
		keyType = undefined
		clientRandom = undefined
		serverRandom = undefined
		processor.reset()

		onTlsEnd?.(error)
	}

	async function getKeyPair(keyType: TLSKeyType) {
		const algorithm = SUPPORTED_NAMED_CURVE_MAP[keyType].algorithm
		keyPairs[keyType] ??= await crypto.generateKeyPair(algorithm)

		return { algorithm, keyPair: keyPairs[keyType] }
	}

	return {
		getMetadata() {
			return {
				cipherSuite,
				keyType,
				version: connTlsVersion,
				selectedAlpn,
			}
		},
		hasEnded() {
			return ended
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

			clientRandom = opts?.random || crypto.randomBytes(32)

			const clientHello = await packClientHello({
				host,
				keysToShare: await Promise.all(
					namedCurves
						.map(async(keyType) => {
							const { keyPair } = await getKeyPair(keyType)
							return {
								type: keyType,
								key: keyPair.pubKey,
							}
						})
				),
				random: clientRandom,
				sessionId,
				psk: opts?.psk,
				cipherSuites,
				supportedProtocolVersions,
				signatureAlgorithms,
				applicationLayerProtocols,
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
		async write(data: Uint8Array) {
			if(!handshakeDone) {
				throw new Error('Handshake not done')
			}

			const chunks = chunkUint8Array(data, MAX_ENC_PACKET_SIZE)
			for(const chunk of chunks) {
				await writeEncryptedPacket({
					data: chunk,
					type: 'WRAPPED_RECORD',
					contentType: 'APPLICATION_DATA'
				})
			}
		},
		end,
	}
}