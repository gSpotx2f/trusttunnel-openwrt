'use strict';
'require form';
'require network';
'require rpc';
'require ui';
'require validation';
'require tools.widgets as widgets';
'require trusttunnel_uri as tturi';

const callGetCertificateFiles = rpc.declare({
	object: 'luci.trusttunnel',
	method: 'getCertificates',
	params: [ 'interface' ],
	expect: { '': {} }
});

const callSetCertificateFiles = rpc.declare({
	object: 'luci.trusttunnel',
	method: 'setCertificates',
	params: [ 'interface', 'endpointCertificate' ],
	expect: { '': {} }
});

function sanitizeCert(s) {
	if (typeof(s) != 'string')
		return '';

	s = s.trim().replace(/\r?\n/g, '\n');

	if (!s.match(/\n$/)) {
		s += '\n';
	};

	return s;
};

function validateCert(priv, section_id, value) {
	if (!value?.trim()) {
		return true;
	};

	const beg    = priv ? /^-----BEGIN (RSA )?PRIVATE KEY-----$/ : /^-----BEGIN CERTIFICATE-----$/;
	const end    = priv ? /^-----END (RSA )?PRIVATE KEY-----$/ : /^-----END CERTIFICATE-----$/;
	const lines  = value.trim().split(/[\r\n]/);
	const base64 = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
	const errmsg = _('This does not look like a valid PEM file');

	if (!lines?.[0].match(beg) || !lines.at(-1).match(end)) {
		return errmsg;
	};

	for (let i = 1; i < lines.length - 1; i++) {
		if (!base64.test(lines[i])) {
			return errmsg;
		};
	};

	return true;
};

const stubValidator = {
	factory: validation,
	apply(type, value, args) {
		if (value != null) {
			this.value = value;
		};
		return validation.types[type].apply(this, args);
	},
	assert(condition) {
		return !!condition;
	},
};

function validatePortsString(section, value) {
	if(value.match(/^((\d+)([:,-](\d+),?)?)*$/)) {
		let units = value.split(',');
		for (let i of units) {
			if (i.includes('-') || i.includes(':')) {
				let p = i.split(/:|-/);
				if (Number(p[0]) <= Number(p[1]) && Number(p[1]) <= 65535) {
					continue;
				} else {
					return `${_('Expecting:')} ${_('valid port range (port1 <= port2)')}`;
				};
			} else {
				if (0 <= Number(i) && Number(i) <= 65535) {
					continue;
				} else {
					return `${_('Expecting:')} ${_('valid port number (0 <= port <= 65535)')}`;
				};
			};
		};
	} else {
		return `${_('Expecting:')} ${_('valid port, comma-separated list of ports or port range (port,port,port1-port2)')}`;
	};
	return true;
};

function validateClientRandom(section, value) {
	return ((/^$|^([a-fA-F0-9]{2})+(\/([a-fA-F0-9]{2})+)?$/i.test(value)) && value.length <= 64) ?
		true : _('Expecting:') + ` ${_('hexstring or hexstring/hexmask')}\n`;
};

function validateExclusions(section, value) {
	if (stubValidator.apply('ipaddr', value) || stubValidator.apply('ipaddrport', value)) {
		return true;
	};

	if (value.length <= 253 && /^$|^(\*\.)?\w[\w.-]+\.[a-zA-Z0-9]+\.?$/.test(value)) {
		return true;
	};

	return _('Expecting:') + ` ${_(' IPAddress, IPAddress:port, IPAddress/mask, domain.name, *.domain.name')}\n`;
};

function validateDNSUpstreams(section, value) {
	if (value.length == 0 || stubValidator.apply('ipaddr', value, [true]) || stubValidator.apply('ipaddrport', value)) {
		return true;
	};

	let r        = value.split('://');
	let scheme   = r[0];
	let resource = r[1];

	switch (scheme) {
		case 'tcp':
			if (stubValidator.apply('ipaddr', resource, [true]) || stubValidator.apply('ipaddrport', resource)) {
				return true;
			};
			break;
		case 'tls':
			if (stubValidator.apply('ipaddr', resource, [true]) || stubValidator.apply('ipaddrport', resource)) {
				return true;
			};
			break;
		;;
		case 'https':
			if (/^([\w.-]+|\[[a-fA-F0-9:.]+\])(:[0-9]{2,5})?((\/|\?).*)?$/.test(resource)) {
				return true;
			};
			break;
		;;
		case 'quic':
			if (stubValidator.apply('host', resource) || stubValidator.apply('hostport', resource)) {
				return true;
			};
			break;
		;;
		case 'sdns':
			if (/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(resource)) {
				return true;
			};
			break;
		;;
	};

	return '%s %s'.format(_('Expecting:'), _('supported DNS server string format'));
};

function newTTClientConfig() {
	return {
		values: {
			loglevel: {
				validator: null,
				expect   : new Set([ 'error', 'warn', 'info', 'debug', 'trace' ]),
				type     : 'string',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'loglevel',
				default  : 'warn',
				value    : null,
			},
			vpn_mode: {
				validator: null,
				expect   : new Set([ 'general', 'selective' ]),
				type     : 'string',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'vpn_mode',
				default  : 'general',
				value    : null,
			},
			exclusions_scannable_ports: {
				validator: v => validatePortsString(null, v) === true,
				expect   : null,
				type     : 'string',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'exclusions_scannable_ports',
				default  : '443,80,8080,8008,853',
				value    : null,
			},
			killswitch_enabled: {
				validator: null,
				expect   : null,
				type     : 'bool',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'killswitch_enabled',
				default  : true,
				value    : null,
			},
			post_quantum_group_enabled: {
				validator: null,
				expect   : null,
				type     : 'bool',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'post_quantum_group_enabled',
				default  : true,
				value    : null,
			},
			exclusions_tcp_early_ack_enabled: {
				validator: null,
				expect   : null,
				type     : 'bool',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'exclusions_tcp_early_ack_enabled',
				default  : false,
				value    : null,
			},
			exclusions_preresolve_enabled: {
				validator: null,
				expect   : null,
				type     : 'bool',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'exclusions_preresolve_enabled',
				default  : true,
				value    : null,
			},
			exclusions_preresolve_max_queries: {
				validator: v => stubValidator.apply('and', v, [ validation.types.uinteger, validation.types.range, [ 0, 300 ] ]),
				expect   : null,
				type     : 'uint',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'exclusions_preresolve_max_queries',
				default  : 50,
				value    : null,
			},
			killswitch_allow_ports: {
				validator: v => stubValidator.apply('port', v),
				expect   : null,
				type     : 'array',
				elemtype : 'uint',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'killswitch_allow_ports',
				default  : [],
				value    : null,
			},
			exclusions: {
				validator: v => validateExclusions(null, v) === true,
				expect   : null,
				type     : 'array',
				elemtype : 'string',
				required : false,
				nonempty : false,
				uri      : null,
				disabled : false,
				uci      : 'exclusions',
				default  : [],
				value    : null,
			},
		},
		tables: {
			'endpoint': {
				addresses: {
					validator: v => stubValidator.apply('hostport', v),
					expect   : null,
					type     : 'array',
					elemtype : 'string',
					required : true,
					nonempty : false,
					uri      : 'addresses',
					disabled : false,
					uci      : 'addresses',
					default  : [],
					value    : null,
				},
				username: {
					validator: null,
					expect   : null,
					type     : 'string',
					required : true,
					nonempty : false,
					uri      : 'username',
					disabled : false,
					uci      : 'username',
					default  : '',
					value    : null,
				},
				password: {
					validator: null,
					expect   : null,
					type     : 'string',
					required : true,
					nonempty : false,
					uri      : 'password',
					disabled : false,
					uci      : 'password',
					default  : '',
					value    : null,
				},
				hostname:{
					validator: v => stubValidator.apply('hostname', v),
					expect   : null,
					type     : 'string',
					required : true,
					nonempty : false ,
					uri      : 'hostname',
					disabled : false,
					uci      : 'hostname',
					default  : '',
					value    : null,
				},
				custom_sni: {
					validator: v => stubValidator.apply('hostname', v),
					expect   : null,
					type     : 'string',
					required : false,
					nonempty : false,
					uri      : 'custom_sni',
					disabled : false,
					uci      : 'custom_sni',
					default  : '',
					value    : null,
				},
				client_random: {
					validator: v => validateClientRandom(null, v) === true,
					expect   : null,
					type     : 'string',
					required : false,
					nonempty : false,
					uri      : 'client_random_prefix',
					disabled : false,
					uci      : 'client_random',
					default  : '',
					value    : null,
				},
				certificate: {
					validator: v => validateCert(false, null, v) === true,
					expect   : null,
					type     : 'string',
					required : false,
					nonempty : true,
					uri      : "certificate",
					disabled : false,
					uci      : 'certificate',
					default  : '',
					value    : null,
				},
				upstream_protocol: {
					validator: null,
					expect   : new Set([ 'http2', 'http3' ]),
					type     : 'string',
					required : false,
					nonempty : false,
					uri      : 'upstream_protocol',
					disabled : false,
					uci      : 'upstream_protocol',
					default  : 'http2',
					value    : null,
				},
				tls_profile: {
					validator: null,
					expect   : new Set([ 'default', 'chrome', 'firefox', 'safari', 'okhttp', 'openssl' ]),
					type     : 'string',
					required : false,
					nonempty : false,
					uri      : 'tls_profile',
					disabled : false,
					uci      : 'tls_profile',
					default  : 'chrome',
					value    : null,
				},
				has_ipv6: {
					validator: null,
					expect   : null,
					type     : 'bool',
					required : false,
					nonempty : false,
					uri      : 'has_ipv6',
					disabled : false,
					uci      : 'has_ipv6',
					default  : true,
					value    : null,
				},
				skip_verification: {
					validator: null,
					expect   : null,
					type     : 'bool',
					required : false,
					nonempty : false,
					uri      : 'skip_verification',
					disabled : false,
					uci      : 'skip_verification',
					default  : false,
					value    : null,
				},
				anti_dpi: {
					validator: null,
					expect   : null,
					type     : 'bool',
					required : false,
					nonempty : false,
					uri      : 'anti_dpi',
					disabled : false,
					uci      : 'anti_dpi',
					default  : false,
					value    : null,
				},
				dns_upstreams: {
					validator: v => validateDNSUpstreams(null, v) === true,
					expect   : null,
					type     : 'array',
					elemtype : 'string',
					required : false,
					nonempty : false,
					uri      : 'dns_upstreams',
					disabled : false,
					uci      : 'dns_upstreams',
					default  : [],
					value    : null,
				},

			},
			'listener.tun': {
				// Not used in OpenWrt
				/*
				bound_if: {
					validator: v => stubValidator.apply('netdevname', v),
					expect   : null,
					type     : 'string',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : true,
					uci      : 'bound_if',
					default  : '',
					value    : null,
				},
				device_name: {
					validator: v => stubValidator.apply('netdevname', v),
					expect   : null,
					type     : 'string',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : true,
					uci      : 'device_name',
					default  : '',
					value    : null,
				},
				change_system_dns: {
					validator: null,
					expect   : null,
					type     : 'bool',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : true,
					uci      : 'change_system_dns',
					default  : false,
					value    : null,
				},
				use_existing: {
					validator: null,
					expect   : null,
					type     : 'bool',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : true,
					uci      : 'use_existing',
					default  : false,
					value    : null,
				},
				*/
				mtu_size: {
					validator: v => stubValidator.apply('and', v, [ validation.types.uinteger, validation.types.range, [ 68, 9200 ] ]),
					expect   : null,
					type     : 'uint',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : false,
					uci      : 'mtu_size',
					default  : 1350,
					value    : null,
				},
				tcp_recv_buf_size: {
					validator: v => v == 0 || stubValidator.apply('uinteger', v) && stubValidator.apply('range', v, [ 4096, 4194304 ]),
					expect   : null,
					type     : 'uint',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : false,
					uci      : 'tcp_recv_buf_size',
					default  : 0,
					value    : null,
				},
				tcp_send_buf_size: {
					validator: v => v == 0 || stubValidator.apply('uinteger', v) && stubValidator.apply('range', v, [ 4096, 4194304 ]),
					expect   : null,
					type     : 'uint',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : false,
					uci      : 'tcp_send_buf_size',
					default  : 0,
					value    : null,
				},
				// Not used in OpenWrt
				/*
				included_routes: {
					validator: v => stubValidator.apply('cidr', v),
					expect   : null,
					type     : 'array',
					elemtype : 'string',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : false,
					uci      : 'included_routes',
					default  : [],
					value    : null,
				},
				excluded_routes: {
					validator: v => stubValidator.apply('cidr', v),
					expect   : null,
					type     : 'array',
					elemtype : 'string',
					required : false,
					nonempty : false,
					uri      : null,
					disabled : false,
					uci      : 'excluded_routes',
					default  : ['0.0.0.0/8', '10.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3'],
					value    : null,
				},
				*/
			},
		},
	};
};

/**
 * Find setting in a TTC dict.
 * ttc - TTC configuration dict.
 * name - setting name from TTC configuration. Optional.
 * attr - setting attribute name (expect, type, uri, uci, default, etc...). Optional.
 * isAttr - attribute value flag: true - attr has value, false - attr has no value, null - doesn't matter. Optional.
 * Returns an array of setting objects.
 *
 * @param {object} ttc
 * @param {string|null} name
 * @param {string|null} attr
 * @param {boolean|null} isAttr
 * @returns {[object...]}
 */
function findSettingsInTTCDict(ttc, name, attr, isAttr) {
	let result = [];
	let find   = (o, t) => {
		for (let [k, v] of Object.entries(o)) {
			if (name === null || k == name) {
				if (attr === null || attr in v) {
					if (isAttr === null || ((!isAttr && !v[attr]) || (isAttr && v[attr]))) {
						result.push({ table: (t || null), name: k, setting: v });
					};
				};
			};
		};
	};
	find(ttc.values, '');
	for (let [k, v] of Object.entries(ttc.tables)) {
		find(v, k);
	};
	return result;
};

String.prototype.trimQuotes = function() {
	return (this.length == 0) ? this : this.replace(/^["']+|["']+$/g, '');
};

function boolToFlag(value) {
	return value ? '1' : '0';
};

function parseTOMLArray(str) {
	return str.replace(/(^\[|\]$)/g, '').split(',').map(e => e.trim().trimQuotes()).filter(e => e !== '');
};

function parseTOMLBool(str) {
	return str === 'true';
};

function convertConfigStringValue(v, type) {
	switch (type) {
		case 'bool':
			return parseTOMLBool(v);
		;;
		case 'uint':
		case 'ufloat':
			return Number(v);
		;;
		case 'array':
			return parseTOMLArray(v);
		;;
	};
	return v;
};

function parseURIData(line) {
	let URIFields = tturi.decodeTTURI(line);

	if (typeof URIFields.addresses == 'string') {
		sURIFields.addresses = [ URIFields.addresses ];
	};
	URIFields.upstream_protocol = URIFields.upstream_protocol.replace('/', '').toLowerCase();
	if (!URIFields.certificate) {
		URIFields.certificate = '';
	};

	let config      = newTTClientConfig();
	let URISettings = findSettingsInTTCDict(config, null, 'uri', true);

	for (let i of URISettings) {
		if (URIFields[i.setting.uri] !== undefined) {
			if (i.table) {
				config.tables[i.table][i.name].value = URIFields[i.setting.uri];
			} else {
				config.values[i.name].value = URIFields[i.setting.uri];
			};
		};
	};

	return config;
};

function parseConfigData(lines) {
	let table  = null;
	let config = newTTClientConfig();

	let multiLineFlag = false;
	let multiLineKey  = null;
	let multiLineVal  = [];
	for (let i of lines) {
		let line = i.replace(/#.*$/, '').trim();
		if (line.length == 0) {
			continue;
		};
		if (multiLineFlag && line) {
			/*
			 * end of multi-line strng or multi-line array
			 */
			if (line.match(/^\s*([^"']*)("""|''')$/) || line.match(/^\s*(\])$/)) {
				multiLineFlag = false;
				multiLineVal.push(RegExp.$1.trim());
				if (multiLineKey) {
					/*
					 * if "multiLineVal" contains a multi-line array, then join it to inline form (with '').
					 * Else join to multi-line string (with '\n').
					 */
					let val      = multiLineVal.join((multiLineVal[0].startsWith('[') && multiLineVal.at(-1).endsWith(']')) ? '' : '\n').trimQuotes();
					multiLineKey = multiLineKey.toLowerCase();

					if (table) {
						if (multiLineKey in config.tables[table]) {
							config.tables[table][multiLineKey].value = convertConfigStringValue(val, config.tables[table][multiLineKey].type);
						};
					} else {
						if (multiLineKey in config.values) {
							config.values[multiLineKey].value = convertConfigStringValue(val, config.tables[table][multiLineKey].type);
						};
					};
				};
				multiLineKey = null;
				multiLineVal = [];
			/*
			 * content of multi-line strng or multi-line array
			 */
			} else {
				multiLineVal.push(line);
			};
		}
		/*
		 * new TOML table
		 */
		else if (line.match(/^\s*\[([\w.]+)\]$/)) {
			table = RegExp.$1.trim().toLowerCase();
		}
		/*
		 * start of multi-line strng or multi-line array
		 */
		else if (line.match(/^\s*"?([\w ."-]+)"?\s*=\s*("""|''')([^"']*)$/) || line.match(/^\s*"?([\w ."-]+)"?\s*=(\s*)(\[)$/)) {
			multiLineFlag = true;
			multiLineKey  = RegExp.$1.trim();
			multiLineVal.push(RegExp.$3.trim());
		}
		/*
		 * key = value
		 */
		else if (line.match(/^\s*"?([\w ."-]+)"?\s*=\s*(.+)$/)) {
			let key = RegExp.$1.trim();
			let val = RegExp.$2.trim();
			if (val.length) {
				key = key.toLowerCase();
				val = val.trimQuotes();
				if (table) {
					if (key in config.tables[table]) {
						config.tables[table][key].value = convertConfigStringValue(val, config.tables[table][key].type);
					};
				} else {
					if (key in config.values) {
						config.values[key].value = convertConfigStringValue(val, config.values[key].type);
					};
				};

			};
		};
	};

	return config;
};

function checkConfig(config) {
	let error = null;

	if (!('tables' in config) || !('values' in config)) {
		return _('configuration is empty');
	};

	let check = (o, t) => {
		if (t) {
			t = `[${t}]`;
		};
		loop:
		for (let [k, v] of Object.entries(o)) {
			if (v.required && v.value === null) {
				error = _('required setting "%s%s" is missing').format(
					t ? (t + '.') : '', k);
				break;
			};

			if (v.nonempty && v.value === null) {
				v.value = v.default;
			};

			if (v.expect && v.value !== null) {
				if (!v.expect.has(v.value)) {
					error = _('setting "%s%s" must contain one of the following values: <b>%s</b>').format(
						t ? (t + '.') : '', k, Array.from(v.expect.keys()).join(', '));
					break;
				};
			} else {
				switch (v.type) {
					case 'bool':
						break;
					;;
					case 'array':
						if (v.value !== null && typeof v.validator == 'function') {
							for (let i of v.value) {
								if (!v.validator(i)) {
									error = _('setting "%s%s" is invalid').format(
										t ? (t + '.') : '', k);
									break loop;
								};
							};
						};
						break;
					;;
					case 'uint':
						if (v.value !== null && !stubValidator.apply('uinteger', v.value)) {
							error = _('setting "%s%s" must be a valid uinteger value').format(
								t ? (t + '.') : '', k);
							break loop;
						};
					case 'ufloat':
						if (v.value !== null && !stubValidator.apply('ufloat', v.value)) {
							error = _('setting "%s%s" must be a valid ufloat value').format(
								t ? (t + '.') : '', k);
							break loop;
						};
					;;
					default:
						if (v.value !== null && v.value !== v.default && typeof v.validator == 'function' && !v.validator(v.value)) {
							error = _('setting "%s%s" is invalid').format(
										t ? (t + '.') : '', k);
							break loop;
						};
					;;
				};
			};
		};
	};

	check(config.values, '');

	for (let [k, v] of Object.entries(config.tables)) {
		check(v, k);
		if (error) {
			break;
		};
	};

	return error;
};

function setConfig(data) {
	let lines  = String(data).replace(/^(\r?\n)+/, '').split(/(\r?\n)+/);
	let config = {};
	let error  = null;

	let firstLine = lines[0].trim();
	if (firstLine.startsWith('tt://')) {
		try {
			if (firstLine.match(/^tt:\/\/\?[a-zA-Z0-9+/=_-]+$/)) {
				config = parseURIData(lines[0]);
			} else {
				throw new SyntaxError(_('invalid URI'));
			}
		} catch (err) {
			error = _('URI parsing error: %s').format(err);
		};
	} else {
		config = parseConfigData(lines);
	};

	if (error === null) {
		error = checkConfig(config);
	};

	return { config, error };
};

return network.registerProtocol('trusttunnel', {
	getI18n() {
		return _('TrustTunnel');
	},

	getIfname() {
		return this._ubus('l3_device') || this.sid;
	},

	getPackageName() {
		return 'trusttunnel-netifd-script';
	},

	isFloating() {
		return true;
	},

	isVirtual() {
		return true;
	},

	getDevices() {
		return null;
	},

	containsDevice(ifname) {
		return (network.getIfnameOf(ifname) == this.getIfname());
	},

	showErrorMessage(elem, error) {
		let errorElem = document.getElementById(`import-error-${this.sid}`);
		if (!errorElem) {
			errorElem = E('div', {
				'id'   : `import-error-${this.sid}`,
				'class': 'alert-message warning',
				'style': 'display:none'
			}, '');
			elem.after(errorElem);
		};
		errorElem.style.display = 'block';
		errorElem.innerHTML     = error;
	},

	hideErrorMessage() {
		let errorElem = document.getElementById(`import-error-${this.sid}`);
		if (errorElem) {
			errorElem.style.display = 'none';
			errorElem.innerHTML     = '';
		};
	},

	applyConfig(s, config) {
		if (!confirm(_('Overwrite the current settings with the imported configuration?'))) {
			return;
		};

		let res               = findSettingsInTTCDict(config, 'certificate', 'value', true);
		let endpointCertValue = (res.length == 0 || !res[0].setting.value) ? '\n' : res[0].setting.value;
		s.getOption('certificate').getUIElement(s.section).setValue(endpointCertValue);

		let setValueFunc = o => {
			for (let v of Object.values(o)) {

				let value = v.value;
				if (value === null || v.disabled || v.uci == 'certificate') {
					continue;
				};
				if (v.type == 'bool') {
					value = boolToFlag(value);
				};

				s.getOption(v.uci).getUIElement(s.section).setValue(value);
			};
		};

		setValueFunc(config.values);

		for (let v of Object.values(config.tables)) {
			setValueFunc(v);
		};

		return s.map.save(null, true);
	},

	showConfig(s, config) {
		let result = [];
		let read   = o => {
			for (let [k, v] of Object.entries(o)) {
				if (v.value === null) {
					continue;
				};
				switch (v.type) {
					case 'bool':
						result.push(`${k} = ${String(v.value)}`);
						break;
					;;
					case 'array':
						let a = v.value;
						if (v.elemtype == 'string') {
							a = a.map(e => `"${e}"`);
						};
						result.push(`${k} = [${a.join(',')}]`);
						break;
					;;
					case 'string':
						if (v.value.includes('\n')) {
							result.push(`${k} = """${v.value}"""`);
						} else {
							result.push(`${k} = "${v.value}"`);
						};
						break;
					;;
					case 'uint':
					case 'ufloat':
						result.push(`${k} = ${v.value}`);
						break;
					;;
				};
			};
		};
		read(config.values);
		for (let [k, v] of Object.entries(config.tables)) {
			result.push(`[${k}]`);
			read(v);
		};

		let configText = result.join('\n');
		if (configText.length > 0) {
			configText += '\n';
		};

		let textarea = s.getOption('import_config').getUIElement(s.section).setValue(configText);

		return Promise.resolve(null);
	},

	handleApplyConfig(s, noapply) {
		let textareaElem = document.getElementById(
			s.getOption('import_config').getUIElement(s.section).options.id).firstChild;
		let input        = textareaElem.value;

		this.hideErrorMessage();

		let r      = setConfig(input);
		let config = r.config;
		let error  = r.error;

		if (error !== null) {
			this.showErrorMessage(textareaElem, _('Cannot parse configuration: %s').format(error));
			return;
		};

		return noapply ? this.showConfig(s, config) : this.applyConfig(s, config);
	},

	renderFormOptions(s) {
		let o;


		/* General */

		// addresses
		o = s.taboption('general', form.DynamicList, 'addresses', _('Addresses'),
			_('Endpoint addresses (IP:port or hostname:port). The exact address is selected by the pinger. Hostnames are resolved via DNS at connect time.'));
		o.rmempty  = false;
		o.datatype = 'hostport';

		// username
		o = s.taboption('general', form.Value, 'username', _('Username'),
			_('Username for authorization.'));
		o.rmempty  = false;
		o.datatype = 'string';

		// password
		o = s.taboption('general', form.Value, 'password', _('Password'),
			_('Password for authorization.'));
		o.password = true;
		o.rmempty  = false;
		o.datatype = 'string';

		// hostname
		o = s.taboption('general', form.Value, 'hostname', _('Hostname'),
			_('Endpoint host name, used for TLS session establishment.'));
		o.rmempty  = false;
		o.datatype = 'hostname';

		// upstream_protocol
		o = s.taboption('general', form.ListValue, 'upstream_protocol', _('Upstream protocol'),
			_(' Protocol to be used to communicate with the endpoint.'));
		o.value('http2');
		o.value('http3');
		o.default = 'http2';

		// skip_verification
		o = s.taboption('general', form.Flag, 'skip_verification', _('Skip verification'),
			_('Skip the endpoint certificate verification? That is, any certificate is accepted if this setting is enabled.'));

		// certificate
		o = s.taboption('general', form.TextValue, 'certificate', _('Endpoint certificate in PEM format'),
			_('If not specified, the endpoint certificate is verified using the system storage.'));
		o.rows      = 10;
		o.monospace = true;
		o.validate  = L.bind(validateCert, o, false);
		o.load      = section_id => {
			return callGetCertificateFiles(section_id).then(certs => certs.endpointCertificate);
		};
		o.write     = (section_id, value) => {
			return callSetCertificateFiles(section_id, sanitizeCert(value));
		};
		o.onchange  = (e, section_id) => e.target.firstChild.spellcheck = false;

		// post_quantum_group_enabled
		o = s.taboption('general', form.Flag, 'post_quantum_group_enabled', _('Post quantum group'),
			_('When enabled, a post-quantum group may be used for key exchange in TLS handshakes initiated by the VPN client.'));
		o.rmempty = false;
		o.default = 1;

		// tls_profile
		o = s.taboption('general', form.ListValue, 'tls_profile', _('TLS profile'),
			_('TLS ClientHello fingerprint to mimic.'));
		o.value('default', _('no mimicry'));
		o.value('chrome');
		o.value('firefox');
		o.value('safari');
		o.value('okhttp');
		o.value('openssl');
		o.default = 'chrome';

		// custom_sni
		o = s.taboption('general', form.Value, 'custom_sni', _('Custom SNI'),
			_('Custom SNI value for TLS handshake. If set, this value is used as the TLS SNI instead of the hostname.'));
		o.datatype = 'hostname';

		// client_random
		o = s.taboption('general', form.Value, 'client_random', _('Client random'),
			_('TLS client random prefix and mask (hex string, format: prefix[/mask]).'));
		o.maxlength = 64;
		o.validate  = validateClientRandom;

		// anti_dpi
		o = s.taboption('general', form.Flag, 'anti_dpi', _('Anti DPI'),
			_('Is anti-DPI measures should be enabled.'));

		// has_ipv6
		o = s.taboption('general', form.Flag, 'has_ipv6', _('IPv6'),
			_('Whether IPv6 traffic can be routed through the endpoint.'));
		o.rmempty = false;
		o.default = 1;

		// included_routes
		o = s.taboption('general', form.DynamicList, 'included_routes', _('Included routes'),
			_('Routes in CIDR notation to set to the virtual interface. If external routing (PBR, MWAN, etc.) is used, must be empty.'));
		o.datatype = 'cidr';

		// interface_dependency
		o = s.taboption('general', widgets.NetworkSelect, 'interface_dependency', _('Interface dependency'),
			_('Name of the network interface used for connections made by the TrustTunnel client.'));
		o.nocreate = true;
		o.exclude  = this.sid;


		/* Advanced */

		// mtu_size
		o = s.taboption('advanced', form.Value, 'mtu_size', _('MTU'),
			_('Maximum Transmission Unit of tunnel interface.'));
		o.placeholder = '1350';
		o.datatype    = 'and(uinteger,range(68,9200))';

		// tcp_recv_buf_size
		o = s.taboption('advanced', form.Value, 'tcp_recv_buf_size', _('TCP receive window size'),
			_('TCP receive window size in bytes. 0 uses optimized default (256 KB). Adjust only for constrained environments.'));
		o.placeholder = '0';
		o.datatype    = 'and(uinteger,or(0,range(4096,4194304)))';

		// tcp_send_buf_size
		o = s.taboption('advanced', form.Value, 'tcp_send_buf_size', _('TCP send buffer size'),
			_('TCP send buffer size in bytes. 0 uses optimized default (256 KB). Adjust only for constrained environments.'));
		o.placeholder = '0';
		o.datatype    = 'and(uinteger,or(0,range(4096,4194304)))';


		/* TrustTunnel */

		s.tab('trusttunnel', _('TrustTunnel Settings'), _('Further information about TrustTunnel at <a href="https://trusttunnel.org/" target="_blank">trusttunnel.org</a> and <a href="https://github.com/TrustTunnel/TrustTunnelClient/blob/master/trusttunnel/README.md#configuration-reference" target="_blank">GitHub</a>.'));

		// vpn_mode
		o = s.taboption('trusttunnel', form.RichListValue, 'vpn_mode', _('VPN mode'),
			_('Defines client connections routing policy.'));
		o.value('general', _('general'),
			_('Route through a VPN endpoint all connections except ones which destinations are in exclusions.'));
		o.value('selective', _('selective'),
			_('Route through a VPN endpoint only the connections which destinations are in exclusions.'));

		// exclusions
		o = s.taboption('trusttunnel', form.DynamicList, 'exclusions', _('Exclusions'),
			_(`Domains and addresses which should be routed in a special manner.<br>
				Supported syntax:
				<dl>
				<dt><b>domain name</b></dt>
				<dd>- if starts with <code>*.</code>, any subdomain of the domain will be matched including www-subdomain, but not the domain itself (e.g., <code>*.example.com</code> will match <code>sub.example.com</code>, <code>sub.sub.example.com</code>, <code>www.example.com</code>, but not <code>example.com</code>)</dd>
				<dd>- if starts with <code>www.</code> or it is just a domain name, the domain itself and its www-subdomain will be matched (e.g. <code>example.com</code> and <code>www.example.com</code> will match <code>example.com</code> <code>www.example.com</code>, but not <code>sub.example.com</code>)</dd>
				<dt><b>IP address</b></dt>
				<i>recognized formats are:</i>
				<dd>- [IPv6Address]:port</dd>
				<dd>- [IPv6Address]</dd>
				<dd>- IPv6Address</dd>
				<dd>- IPv4Address:port</dd>
				<dd>- IPv4Address</dd>
				<i>if port is not specified, any port will be matched</i>
				<dt><b>CIDR range</b></dt>
				<i>recognized formats are:</i>
				<dd>- IPv4Address/mask</dd>
				<dd>- IPv6Address/mask</dd>
				</dl>
			`));
		o.validate = validateExclusions;

		// exclusions_scannable_ports
		o = s.taboption('trusttunnel', form.Value, 'exclusions_scannable_ports', _('Exclusions scannable ports'),
			_('Comma-separated list of ports considered "scannable" for domain extraction and exclusion matching. Supports individual ports and ranges, e.g. <code>443,80,8080:8090,853</code>. If empty, the default list is used.'));
		o.placeholder = '443,80,8080,8008,853';
		o.validate    = validatePortsString;

		// dns_upstreams
		o = s.taboption('trusttunnel', form.DynamicList, 'dns_upstreams', _('DNS upstreams'),
			_(`DNS resolvers for queries routed through VPN. If empty, AdGuard DNS unfiltered is used. Supported one of the following kinds:<br>
				- <code>8.8.8.8:53</code> - %s<br>
				- <code>tcp://8.8.8.8:53</code> - %s<br>
				- <code>tls://1.1.1.1</code> - %s<br>
				- <code>https://dns.adguard.com/dns-query</code> - %s<br>
				- <code>quic://dns.adguard.com:8853</code> - %s<br>
				- <code>sdns://...</code> - %s (see <a href="https://dnscrypt.info/stamps-specifications" target="_blank">https://dnscrypt.info/stamps-specifications</a>)
			`).format(
				_('plain DNS'), _('plain DNS over TCP'), _('DNS-over-TLS'),
				_('DNS-over-HTTPS'), _('DNS-over-QUIC'), _('DNS stamp')
			)
		);
		o.rmempty  = false;
		o.validate = validateDNSUpstreams;

		// killswitch_enabled
		o = s.taboption('trusttunnel', form.Flag, 'killswitch_enabled', _('Killswitch enabled'),
			_('When disabled, all connection requests are routed directly to target hosts in case connection to VPN endpoint is lost. This helps not to break an Internet connection if user has poor connectivity to an endpoint. When enabled, incoming connection requests which should be routed through an endpoint will not be routed directly in that case.'));
		o.rmempty = false;
		o.default = 1;

		// killswitch_allow_ports
		o = s.taboption('trusttunnel', form.DynamicList, 'killswitch_allow_ports', _('Killswitch allow ports'),
			_('When the kill switch is enabled, allow inbound connections to these local ports.'));
		o.datatype = 'port';

		// exclusions_tcp_early_ack_enabled
		o = s.taboption('trusttunnel', form.Flag, 'exclusions_tcp_early_ack_enabled', _('Exclusions TCP early ACK enabled'),
			_('When enabled, all TCP connections to scannable ports are initially routed through a fake upstream to read the TLS SNI before making any real connection. This ensures site exclusions work correctly when a secure DNS resolver is configured outside of AdGuard VPN, or when the exclusion list contains wildcard entries (e.g. <code>*.example.com</code>).'));

		// exclusions_preresolve_enabled
		o = s.taboption('trusttunnel', form.Flag, 'exclusions_preresolve_enabled', _('Exclusions preresolve enabled'),
			_('When enabled, DNS-resolvable exclusions are pre-resolved in the background after the exclusion list is updated. This populates the suspects cache so that connections to excluded hosts are routed correctly without waiting for the first DNS response.'));
		o.rmempty = false;
		o.default = 1;

		// exclusions_preresolve_max_queries
		o = s.taboption('trusttunnel', form.Value, 'exclusions_preresolve_max_queries', _('Exclusions preresolve max queries'),
			_('Maximum number of exclusion domains to pre-resolve per cycle.'));
		o.placeholder = '50';
		o.datatype    = 'and(uinteger,range(0,300))';

		// loglevel
		o = s.taboption('trusttunnel', form.ListValue, 'loglevel', _('Logging level'));
		o.value('error');
		o.value('warn');
		o.value('info');
		o.value('debug');
		o.value('trace');
		o.default = 'warn';

		s.tab('import', _('Import configuration'),
			  _('Here, you can import TrustTunnel client settings from a deeplink URI (<code>tt://...</code>) or the contents of a TOML configuration file.'));

		o = s.taboption('import', form.TextValue, 'import_config', _('URI or TOML configuration'),
			_('Supports a deeplink TrustTunnel URI (tt://...) or TOML configuration file content.'));
		o.rows        = 20;
		o.monospace   = true;
		o.placeholder = _('Paste supplied TrustTunnel URI (tt://...) or TOML configuration…');
		o.wrap        = true;
		o.load        = () => {};
		o.write       = () => {};
		o.onchange    = (ev, section_id) => ev.target.firstChild.spellcheck = false;

		o = s.taboption('import', form.Button, '_decode_uri_btn', _('Decode URI'),
			_('Decode the inserted URI into TOML configuration without importing settings.'));
		o.onclick    = () => this.handleApplyConfig(s, true);
		o.inputtitle = _('Decode');
		o.inputstyle = 'neutral';

		o = s.taboption('import', form.Button, '_import_btn', _('Import settings'));
		o.onclick    = () => this.handleApplyConfig(s);
		o.inputtitle = _('Import settings');
		o.inputstyle = 'action primary important';
	},
});
