<div>
    <div>
        <img src="https://raw.githubusercontent.com/reclaimprotocol/.github/main/assets/banners/TLS.png"  />
    </div>
</div>

A TLS client implementation in typescript. This library is fully compatible with the browser (without any polyfills), and on any other JavaScript environment.

As all the cryptography is handled by either "webcrypto" or a "pure-js" implementation if webcrypto is not available.

## Dependencies

1. The ChaCha20-Poly1305 cipher is not supported via WebCrypto -- so we utilise `@stablelib/chacha20-poly1305` to provide this functionality.
2. To handle X509 certificate validation we utilise `@peculiar/x509`

## Supported Crypto Suites & Versions

### TLS
- TLS 1.2
- TLS 1.3

### Curves
- X25519 (only on NodeJs -- not supported in the browser)
- P-256 (SECP256R1)
- P-384 (SECP384R1)

### Signature Algorithms
- RSA-PSS-RSAE-SHA256
- ECDSA-SECP256R1-SHA256
- ECDSA-SECP384R1-SHA384
- RSA-PKCS1-SHA256
- RSA-PKCS1-SHA384
- RSA-PKCS1-SHA512

### Cipher Suites (TLS 1.3)
- AES-128-GCM-SHA256
- AES-256-GCM-SHA384
- CHACHA20-POLY1305-SHA256

### Cipher Suites (TLS 1.2)
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA

### Certificates
- The entire Mozilla CA store is supported
- A few additional certificates have also been added. See `src/utils/root-ca.ts`

## Install

Edge version:
``` sh
npm i git+https://github.com/reclaimprotocol/tls
```

## Set Crypto Implementation

When on the browser, NodeJS or another NodeJS like runtime (such as Bun), you can set the crypto implementation to use the native `webcrypto` API. This is the most performant way to use this library.
``` ts
import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'

setCryptoImplementation(webcryptoCrypto)
```

If webcrypto is not available, you can use the `pure-js` implementation. This is slower, but works in all JavaScript environments -- even JavascriptCore.
``` ts
import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { pureJsCrypto } from '@reclaimprotocol/tls/pure-js'

setCryptoImplementation(pureJsCrypto)
```

## Example Usage

After you've set the crypto implementation, you can use the TLS client like this:

``` ts
import { Socket } from 'net'
import { makeTLSClient, uint8ArrayToStr } from '@reclaimprotocol/tls'

const socket = new Socket()
const host = 'www.google.com'
const port = 443

const tls = makeTLSClient({
	host,
	// verify the server's certificate
	// disable when using self-signed certificates
	// or if you don't care about the authenticity
	// of the server
	verifyServerCertificate: true,
	// only use the following cipher suites
	// leave undefined to use all supported cipher suites
	cipherSuites: [
		'TLS_CHACHA20_POLY1305_SHA256'
		// ... other suites
	],
	// write raw bytes to the socket
	async write({ header, content }) {
		socket.write(header)
		socket.write(content)
	},
	onHandshake() {
		console.log('handshake completed successfully')
		// write encrypted data to the socket
		const getReq = `GET / HTTP/1.1\r\nHost: ${host}\r\n\r\n`
		tls.write(Buffer.from(getReq))
	},
	onApplicationData(plaintext) {
		const str = uint8ArrayToStr(plaintext)
		console.log('received application data: ', str)
	},
	onTlsEnd(error) {
		console.error('TLS connect ended: ', error)
	}
})

socket.on('data', tls.handleReceivedBytes)

// start handshake as soon as the socket connects
socket.on('connect', () => tls.startHandshake())

// use the TCP socket to connect to the server
socket.connect({ host, port })
```

### Misc API Usage

Handle a Session Ticket & Resume Session with a PSK
``` ts
const tlsClient = makeTlsClient({
	// ... other options
	onSessionTicket(ticket) {
		// get a PSK (pre-shared key) from the session ticket
		const psk = tls.getPskFromTicket(ticket)
		// this can be used to resume a session
		// if disconnected, using
		// tls.startHandshake({ psk })
	}
})
```

Handle received certificates
``` ts
const tlsClient = makeTlsClient({
	// ... other options

	// handle received certificates
	// (if you want to for some reason)
	onRecvCertificates({ certificates }) {
		// do something I guess?
	}
})
```

Use the TLS KeyUpdate method to update the traffic keys. This sends a KeyUpdate message to the server & generates a fresh set of keys to encrypt/decrypt data. The server will then respond with a KeyUpdate message of its own. This is useful for forward secrecy.
```ts
await tls.updateTrafficKeys()
```

## Testing

Once you clone the repository, install dependencies via `npm i`, you can run the tests using:
```bash
npm run test:webcrypto
```
to test the WebCrypto implementation, or
```bash
npm run test:pure-js
```
to test the PureJS implementation.

If you want to test a connection to a host, you can use the `handshake.ts` script. This script will connect to the specified host and port, perform a TLS handshake, and log the result.
```bash
npm run handshake -- --host www.google.com
```

if you want to test `javascriptcore` compatibility, you can run the [jsc](/src/tests/jsc.test_mac.ts) test. This will run the tests in a JavaScriptCore environment, which is useful for testing compatibility with an ECMAScript environment that does not support WebCrypto.
Before you run the `jsc` test, make sure you have the `jsc` binary installed on your system & have built the `jsc` file using the `npm run build:jsc` command.

## Updating CA certificates
```bash
npm run update:root-ca
```

## Contributing to Our Project

We're excited that you're interested in contributing to our project! Before you get started, please take a moment to review the following guidelines.

## Code of Conduct

Please read and follow our [Code of Conduct](https://github.com/reclaimprotocol/.github/blob/main/Code-of-Conduct.md) to ensure a positive and inclusive environment for all contributors.

## Security

If you discover any security-related issues, please refer to our [Security Policy](https://github.com/reclaimprotocol/.github/blob/main/SECURITY.md) for information on how to responsibly disclose vulnerabilities.

## Contributor License Agreement

Before contributing to this project, please read and sign our [Contributor License Agreement (CLA)](https://github.com/reclaimprotocol/.github/blob/main/CLA.md).

## Indie Hackers

For Indie Hackers: [Check out our guidelines and potential grant opportunities](https://github.com/reclaimprotocol/.github/blob/main/Indie-Hackers.md)

## License

This project is licensed under a [custom license](https://github.com/reclaimprotocol/.github/blob/main/LICENSE). By contributing to this project, you agree that your contributions will be licensed under its terms.

Thank you for your contributions!
