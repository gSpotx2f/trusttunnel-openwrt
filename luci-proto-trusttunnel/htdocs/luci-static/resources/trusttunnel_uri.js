'use strict';
'require baseclass';

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LOOKUP = (() => {
	const table = {};
	for (let i = 0; i < BASE64_ALPHABET.length; i++) {
		table[BASE64_ALPHABET[i]] = i;
	};
	return table;
})();

function base64Encode(bytes) {
	let out   = '';
	const len = bytes.length;

	for (let i = 0; i < len; i += 3) {
		const b0   = bytes[i];
		const has1 = i + 1 < len;
		const has2 = i + 2 < len;
		const b1   = has1 ? bytes[i + 1] : 0;
		const b2   = has2 ? bytes[i + 2] : 0;

		const triple = (b0 << 16) | (b1 << 8) | b2;

		out += BASE64_ALPHABET[(triple >>> 18) & 0x3f];
		out += BASE64_ALPHABET[(triple >>> 12) & 0x3f];
		out += has1 ? BASE64_ALPHABET[(triple >>> 6) & 0x3f] : '=';
		out += has2 ? BASE64_ALPHABET[triple & 0x3f] : '=';
	};

	return out;
}

function base64Decode(input) {
	const cleaned = String(input).replace(/[^A-Za-z0-9+/=]/g, '');
	const body    = cleaned.replace(/=+$/, '');

	if (body.length % 4 === 1) {
		throw new Error('invalid base64 length');
	}

	const out    = new Uint8Array(Math.floor((body.length * 6) / 8));
	let outIndex = 0;
	let buffer   = 0;
	let bits     = 0;

	for (let i = 0; i < body.length; i++) {
		const ch    = body[i];
		const value = BASE64_LOOKUP[ch];
		if (value === undefined) {
			throw new Error(`invalid base64 character: '${ch}'`);
		};

		buffer = (buffer << 6) | value;
		bits   += 6;

		if (bits >= 8) {
			bits -= 8;
			out[outIndex++] = (buffer >>> bits) & 0xff;
		};
	};

	return outIndex === out.length ? out : out.subarray(0, outIndex);
};

function toUint8Array(data) {
	if (data instanceof Uint8Array) {
		return data;
	};
	if (Array.isArray(data)) {
		return Uint8Array.from(data);
	};
	throw new TypeError('expected a Uint8Array, Buffer or number[]');
}

function parsePemCertificates(pem) {
	const certs   = [];
	const beginRe = /-----BEGIN ([A-Za-z0-9 ]+)-----/g;
	let match;

	while ((match = beginRe.exec(pem)) !== null) {
		const label     = match[1];

		const endMarker = `-----END ${label}-----`;

		const bodyStart = match.index + match[0].length;
		const endIndex  = pem.indexOf(endMarker, bodyStart);

		if (endIndex === -1) {
			throw new Error(
				`PEM parsing failed: missing "${endMarker}" for block starting at offset ${match.index}`);
		};

		if (label.toUpperCase() === 'CERTIFICATE') {
			const body = pem.slice(bodyStart, endIndex);

			let der;
			try {
				der = base64Decode(body);
			} catch (e) {
				throw new Error(`PEM parsing failed: ${e}`);
			};

			if (der.length === 0) {
				throw new Error(
					'PEM parsing failed: empty base64 payload in CERTIFICATE block');
			};

			certs.push(der);
		};

		beginRe.lastIndex = endIndex + endMarker.length;
	};

	return certs;
};

function readAsn1Length(data, offset) {
	if (offset >= data.length) {
		throw new Error('unexpected end of data in ASN.1 length');
	};

	const first = data[offset];

	if (first < 0x80) {
		return [first, offset + 1];
	};

	const numBytes = first & 0x7f;

	if (numBytes === 0 || offset + 1 + numBytes > data.length) {
		throw new Error('invalid ASN.1 length encoding');
	};

	let length = 0;
	for (let i = 0; i < numBytes; i++) {
		length = length * 256 + data[offset + 1 + i];
	};

	if (!Number.isSafeInteger(length)) {
		throw new Error('ASN.1 length exceeds safe integer range');
	};

	return [length, offset + 1 + numBytes];
};

function splitDerCerts(data) {
	const certs = [];
	let offset  = 0;

	while (offset < data.length) {
		if (data[offset] !== 0x30) {
			throw new Error(
				`expected ASN.1 SEQUENCE (0x30) at offset ${offset}, got 0x${data[offset]
					.toString(16).toUpperCase().padStart(2, '0')}`
			);
		};

		const [bodyLen, hdrEnd] = readAsn1Length(data, offset + 1);

		const certEnd = hdrEnd + bodyLen;
		if (!Number.isSafeInteger(certEnd)) {
			throw new Error('certificate length overflow');
		};

		if (certEnd > data.length) {
			throw new Error('truncated DER certificate');
		};

		certs.push(data.slice(offset, certEnd));
		offset = certEnd;
	};

	return certs;
};

function derToPem(der) {
	const data = toUint8Array(der);
	const certs = splitDerCerts(data);
	const pemBlocks = [];

	for (const certDer of certs) {
		const b64   = base64Encode(certDer);

		const lines = [];
		for (let i = 0; i < b64.length; i += 64) {
			lines.push(b64.slice(i, i + 64));
		};

		pemBlocks.push(
			`-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`
		);
	};

	return `${pemBlocks.join('\n')}\n`;
};

/*
 * Functions for decoding TrustTunnel URI (tt://...).
 * Source: https://trusttunnel.org/qr.html.
 * (c) AdGuard Software Limited.
 */
// --- Base64url decoding ---
function base64urlToBytes(str) {
	// Restore standard Base64: replace URL-safe chars and add padding
	let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
	while (b64.length % 4 !== 0) {
		b64 += '=';
	};
	let binary = atob(b64);
	let bytes  = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	};
	return bytes;
};

// --- TLS varint decoding (RFC 9000 §16) ---
function readVarint(buf, offset) {
	if (offset >= buf.length) {
		throw new Error('Unexpected end of buffer reading varint');
	};
	let first  = buf[offset];
	let prefix = first >> 6;
	let len = 1 << prefix; // 1, 2, 4, or 8 bytes
	if (offset + len > buf.length) {
		throw new Error('Unexpected end of buffer reading varint');
	};
	let value = first & 0x3f;
	for (let i = 1; i < len; i++) {
		value = value * 256 + buf[offset + i];
	};
	return { value: value, bytesRead: len };
}

// --- TLV parser ---
let FIELD_TAGS = {
	0x00: 'version',
	0x01: 'hostname',
	0x02: 'addresses',
	0x03: 'custom_sni',
	0x04: 'has_ipv6',
	0x05: 'username',
	0x06: 'password',
	0x07: 'skip_verification',
	0x08: 'certificate',
	0x09: 'upstream_protocol',
	0x0A: 'anti_dpi',
	0x0B: 'client_random_prefix',
	0x0C: 'name',
	0x0D: 'dns_upstreams',
};

let UPSTREAM_PROTOCOL_MAP = {
	0x01: 'HTTP/2',
	0x02: 'HTTP/3',
};

function parseTLV(bytes) {
	let config = {
		name                : null,
		hostname            : null,
		addresses           : [],
		custom_sni          : null,
		has_ipv6            : true,
		username            : null,
		password            : null,
		skip_verification   : false,
		certificate         : false,
		upstream_protocol   : 'HTTP/2',
		anti_dpi            : false,
		client_random_prefix: null,
		dns_upstreams       : [],
	};

	let offset  = 0;
	let decoder = new TextDecoder('utf-8');

	while (offset < bytes.length) {
		let tagResult = readVarint(bytes, offset);
		offset        += tagResult.bytesRead;

		let lenResult = readVarint(bytes, offset);
		offset        += lenResult.bytesRead;

		let tag       = tagResult.value;
		let len       = lenResult.value;

		if (offset + len > bytes.length) {
			throw new Error('TLV value exceeds buffer length');
		};

		let value = bytes.slice(offset, offset + len);
		offset    += len;

		let fieldName = FIELD_TAGS[tag];
		if (!fieldName) {
			// Unknown tag — skip per spec
			continue;
		};

		switch (tag) {
			case 0x01: // hostname
				config.hostname = decoder.decode(value);
				break;
			case 0x02: // addresses (may repeat)
				config.addresses.push(decoder.decode(value));
				break;
			case 0x03: // custom_sni
				config.custom_sni = decoder.decode(value);
				break;
			case 0x04: // has_ipv6
				config.has_ipv6 = value[0] === 0x01;
				break;
			case 0x05: // username
				config.username = decoder.decode(value);
				break;
			case 0x06: // password
				config.password = decoder.decode(value);
				break;
			case 0x07: // skip_verification
				config.skip_verification = value[0] === 0x01;
				break;
			case 0x08: // certificate (binary DER)
				config.certificate = derToPem(value);
				break;
			case 0x09: // upstream_protocol
				config.upstream_protocol = UPSTREAM_PROTOCOL_MAP[value[0]] || 'Unknown';
				break;
			case 0x0A: // anti_dpi
				config.anti_dpi = value[0] === 0x01;
				break;
			case 0x0B: // client_random_prefix
				config.client_random_prefix = decoder.decode(value);
				break;
			case 0x0C: // name
				config.name = decoder.decode(value);
				break;
			case 0x0D: // dns_upstreams (String[] — length-prefixed sequence)
				let dnsOffset = 0;
				while (dnsOffset < value.length) {
					let dnsLenResult = readVarint(value, dnsOffset);
					dnsOffset        += dnsLenResult.bytesRead;

					if (dnsOffset + dnsLenResult.value > value.length) {
						throw new Error('dns_upstreams entry exceeds buffer length');
					};
					let dnsEntry = decoder.decode(value.slice(dnsOffset, dnsOffset + dnsLenResult.value));
					dnsOffset    += dnsLenResult.value;
					config.dns_upstreams.push(dnsEntry);
				};
				break;
		};
	};

	// Validate required fields
	if (!config.hostname) {
		throw new Error('Missing required field: hostname');
	};
	if (config.addresses.length === 0) {
		throw new Error('Missing required field: addresses');
	};
	if (!config.username) {
		throw new Error('Missing required field: username');
	};
	if (!config.password) {
		throw new Error('Missing required field: password');
	};

	return config;
}

// --- Render everything for a given payload ---
function renderPayload(payload) {
	let bytes  = base64urlToBytes(payload);
	let config = parseTLV(bytes);
	return config;
};

// --- Extract payload from a tt:// link ---
function getPayloadFromLink(link) {
	let trimmed = link.trim();
	let prefix  = 'tt://?';
	if (trimmed.substring(0, prefix.length) !== prefix) {
		return null;
	};
	let payload = trimmed.substring(prefix.length);
	return payload.length > 0 ? payload : null;
}

return baseclass.extend({
	decodeTTURI(str) {
		return renderPayload(getPayloadFromLink(str));
	},
});
