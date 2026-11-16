'use strict';
'require baseclass';

/*
 * Functions for decoding TrustTunnel URI (tt://...).
 * Source: https://trusttunnel.org/qr.html.
 * (c) AdGuard Software Limited.
 */
var SUPPORTED_VERSION = 2;

var PROTOCOL_HTTP2 = 1;
var PROTOCOL_HTTP3 = 2;
var PROTOCOL_NAMES = {
	1: 'HTTP/2',
	2: 'HTTP/3'
};

// --- Base64url (RFC 4648 section 5, no padding) ---
function base64urlToBytes(str) {
	var b64 = String(str).replace(/-/g, '+').replace(/_/g, '/');
	while (b64.length % 4 !== 0) {
		b64 += '=';
	}
	var binary = atob(b64);
	var bytes = new Uint8Array(binary.length);
	for (var i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

// --- TLS varint (RFC 9000 section 16) ---
function readVarint(buf, offset) {
	if (offset >= buf.length) {
		throw new Error('Unexpected end of buffer reading varint');
	}
	var first = buf[offset];
	var prefix = first >> 6;
	var len = 1 << prefix;
	if (offset + len > buf.length) {
		throw new Error('Unexpected end of buffer reading varint');
	}
	var value = first & 0x3f;
	for (var i = 1; i < len; i++) {
		value = value * 256 + buf[offset + i];
	}
	return { value: value, bytesRead: len };
}

// --- Client random validation (hex, optional mask) ---
function validateClientRandomPrefix(value) {
	var parts = value.split('/');
	if (parts.length > 2) {
		return 'Client Random must have the form prefix or prefix/mask.';
	}
	if (!/^[0-9a-fA-F]+$/.test(parts[0])) {
		return 'The Client Random prefix must contain only hexadecimal characters.';
	}
	if (parts[0].length % 2 !== 0) {
		return 'The Client Random prefix must have an even number of characters.';
	}
	if (parts.length === 2) {
		if (!/^[0-9a-fA-F]*$/.test(parts[1])) {
			return 'The Client Random mask must contain only hexadecimal characters.';
		}
		if (parts[1].length % 2 !== 0) {
			return 'The Client Random mask must have an even number of characters.';
		}
	}
	return null;
}

function validateHexKey(value, label) {
	if (!/^[0-9a-fA-F]+$/.test(value)) {
		return label + ' must contain only hexadecimal characters.';
	}
	if (value.length % 2 !== 0) {
		return label + ' must have an even number of characters.';
	}
	return null;
}

function readBool(value, fieldName) {
	if (value.length !== 1 || (value[0] !== 0x00 && value[0] !== 0x01)) {
		throw new Error('Invalid ' + fieldName + ' value');
	}
	return value[0] === 0x01;
}

// --- Decode ---
function extractPayload(input) {
	var value = String(input === null || input === undefined ? '' : input).trim();
	if (value.indexOf('tt://?') === 0) {
		return value.slice(6);
	}
	if (value.indexOf('tt://') === 0) {
		// Legacy format: tt://<base64url>, without the query marker.
		return value.slice(5);
	}
	if (value.indexOf('#tt=') === 0) {
		return value.slice(4);
	}
	if (value.indexOf('tt=') === 0) {
		return value.slice(3);
	}
	return value;
}

function parseTLV(bytes) {
	var config = {
		version: 0,
		name: null,
		hostname: null,
		addresses: [],
		custom_sni: null,
		has_ipv6: true,
		username: null,
		password: null,
		skip_verification: false,
		certificate_der: null,
		upstream_protocol: 'HTTP/2',
		anti_dpi: false,
		client_random_prefix: null,
		client_random_auth_key: null,
		subscription_url: null,
		dns_upstreams: []
	};

	var offset = 0;
	var decoder = new TextDecoder('utf-8');

	while (offset < bytes.length) {
		var tagResult = readVarint(bytes, offset);
		offset += tagResult.bytesRead;

		var lenResult = readVarint(bytes, offset);
		offset += lenResult.bytesRead;

		var tag = tagResult.value;
		var len = lenResult.value;

		if (offset + len > bytes.length) {
			throw new Error('TLV value exceeds buffer length');
		}

		var value = bytes.slice(offset, offset + len);
		offset += len;

		switch (tag) {
			case 0x00: // version
				config.version = readVarint(value, 0).value;
				if (config.version > SUPPORTED_VERSION) {
					throw new Error('This link uses deep-link format version ' + config.version +
						'. This page supports version ' + SUPPORTED_VERSION +
						' or lower. Download a newer version of this page.');
				}
				break;
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
				config.has_ipv6 = readBool(value, 'has_ipv6');
				break;
			case 0x05: // username
				config.username = decoder.decode(value);
				break;
			case 0x06: // password
				config.password = decoder.decode(value);
				break;
			case 0x07: // skip_verification
				config.skip_verification = readBool(value, 'skip_verification');
				break;
			case 0x08: // certificate (binary DER)
				config.certificate_der = value.length > 0 ? value : null;
				break;
			case 0x09: // upstream_protocol
				if (value.length !== 1 || (value[0] !== PROTOCOL_HTTP2 && value[0] !== PROTOCOL_HTTP3)) {
					throw new Error('Invalid upstream_protocol value');
				}
				config.upstream_protocol = PROTOCOL_NAMES[value[0]];
				break;
			case 0x0A: // anti_dpi
				config.anti_dpi = readBool(value, 'anti_dpi');
				break;
			case 0x0B: // client_random_prefix
				config.client_random_prefix = decoder.decode(value);
				var prefixError = validateClientRandomPrefix(config.client_random_prefix);
				if (prefixError) {
					throw new Error('Invalid client_random_prefix: ' + prefixError);
				}
				break;
			case 0x0C: // name
				config.name = decoder.decode(value);
				break;
			case 0x0D: // dns_upstreams (String[]: varint length + UTF-8 bytes)
				var dnsOffset = 0;
				while (dnsOffset < value.length) {
					var dnsLenResult = readVarint(value, dnsOffset);
					dnsOffset += dnsLenResult.bytesRead;

					if (dnsOffset + dnsLenResult.value > value.length) {
						throw new Error('dns_upstreams entry exceeds buffer length');
					}
					var dnsEntry = decoder.decode(value.slice(dnsOffset, dnsOffset + dnsLenResult.value));
					dnsOffset += dnsLenResult.value;
					config.dns_upstreams.push(dnsEntry);
				}
				break;
			case 0x0E: // subscription_url
				config.subscription_url = decoder.decode(value);
				if (config.subscription_url.indexOf('https://') !== 0) {
					throw new Error('The subscription URL must start with https://.');
				}
				break;
			case 0x0F: // client_random_auth_key
				config.client_random_auth_key = decoder.decode(value);
				var authKeyError = validateHexKey(config.client_random_auth_key, 'Client Random auth key');
				if (authKeyError) {
					throw new Error('Invalid client_random_auth_key: ' + authKeyError);
				}
				break;
			default:
				// Unknown tags are ignored for forward compatibility.
				break;
		}
	}

	// Static connection parameters are optional when a subscription URL is
	// present. They act as a fallback for the first connection attempt.
	if (!config.subscription_url) {
		if (!config.hostname) throw new Error('Missing required field: hostname');
		if (config.addresses.length === 0) throw new Error('Missing required field: addresses');
		if (!config.username) throw new Error('Missing required field: username');
		if (!config.password) throw new Error('Missing required field: password');
	}

	return config;
}

function decodePayload(payload) {
	if (!payload) {
		throw new Error('The link does not contain a TrustTunnel configuration payload.');
	}
	return parseTLV(base64urlToBytes(payload));
}

function decode(uri) {
	return decodePayload(extractPayload(uri));
}

function readAsn1Length(bytes, offset) {
	if (offset >= bytes.length) {
		throw new Error('Unexpected end of DER data');
	}
	var first = bytes[offset];
	if (first < 0x80) {
		return { length: first, next: offset + 1 };
	}
	var count = first & 0x7f;
	if (count === 0 || count > 4 || offset + 1 + count > bytes.length) {
		throw new Error('Invalid DER certificate length');
	}
	var length = 0;
	for (var i = 0; i < count; i++) {
		length = length * 256 + bytes[offset + 1 + i];
	}
	return { length: length, next: offset + 1 + count };
}

function derToPem(derBytes) {
	var certs = [];
	var offset = 0;
	while (offset < derBytes.length) {
		if (derBytes[offset] !== 0x30) {
			throw new Error('Invalid DER certificate data');
		}
		var lenResult = readAsn1Length(derBytes, offset + 1);
		var certEnd = lenResult.next + lenResult.length;
		if (certEnd > derBytes.length) {
			throw new Error('Invalid DER certificate length');
		}
		certs.push(derBytes.slice(offset, certEnd));
		offset = certEnd;
	}
	if (certs.length === 0) {
		throw new Error('No certificate data');
	}
	return certs.map(function (cert) {
		var binary = '';
		for (var i = 0; i < cert.length; i++) {
			binary += String.fromCharCode(cert[i]);
		}
		var lines = btoa(binary).match(/.{1,64}/g) || [];
		return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----';
	}).join('\n') + '\n';
}

return baseclass.extend({
	decodeTTURI(str) {
		let config = decode(str);
		if (config.certificate_der) {
			config.certificate = derToPem(config.certificate_der);
		};
		return config;
	},
});
