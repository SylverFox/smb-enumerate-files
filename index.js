const net = require('net')
const ntlm = require('ntlm')

// SMB message command opcodes
const NEGOTIATE = 0x00
const SESSION_SETUP = 0x01
const TREE_CONNECT = 0x03
const CREATE = 0x05
const CLOSE = 0x06
const QUERY_DIRECTORY = 0x0e

// common error codes
const COMMON_ERRORS = {
	0xc000000d: 'STATUS_INVALID_PARAMETER',
	0xc0000022: 'STATUS_ACCESS_DENIED',
	0xc000005e: 'STATUS_NO_LOGON_SERVERS',
	0xc000006d: 'STATUS_LOGON_FAILURE',
	0xc0000072: 'STATUS_ACCOUNT_DISABLED',
	0xc00000bb: 'STATUS_NOT_SUPPORTED',
	0xC0000033: 'STATUS_OBJECT_NAME_INVALID',
	0xC0000034: 'STATUS_OBJECT_NAME_NOT_FOUND',
	0xc000003a: 'STATUS_OBJECT_PATH_NOT_FOUND',
	0xC00000CC: 'STATUS_BAD_NETWORK_NAME'
}

const NETBIOS_HEADER = '00000000'

const SMB_HEADER = 'fe534d4240' + '0'.repeat(118)

const REQUEST_STRUCTURES = {
	[NEGOTIATE]:  '24000200010000000000000000000000000000000000000000000000000000000000000002021002',
	[SESSION_SETUP]: '190000010100000000000000580000000000000000000000',
	[TREE_CONNECT]: '0900000048000000',
	[CREATE]: '39000000020000000000000000000000000000000000000000000080'
		+ '00000000070000000100000001000000780000000000000000000000',
	[CLOSE]: '180000000000000000000000000000000000000000000000',
	[QUERY_DIRECTORY]: '2100250000000000000000000000000000000000000000006000000000000100'
}

/**
 * Enumerates a directory on a share given in the options. Returns a promise that resolves into a
 * list of files and directories in that folder.
 * @param {object|string} options - An smb url string or object with the same arguments
 */
exports.enumerate = async options => {
	options = parseOptions(options)
	const session = this.createSession(options)
	try {
		await session.connect()
		const files = await session.enumerate(options.path)
		return files
	} catch(err) {
		throw err
	} finally {
		session.close()
	}
}

/**
 * Creates a new SMB session that can also be used to enumerate files. This requires a manual
 * connect and close operation.
 * @param {object|string} options - An smb url string or object with the same arguments
 */
exports.createSession = options => new SMBSession(parseOptions(options))

function parseOptions(options) {
	let _options = {port: 445, username: 'guest', password: '', domain: 'WORKGROUP'}
	if(typeof options === 'string') {
		const smbUrlRe =
      /^smb:\/\/(?:(?:(.*?);)?(.*?)(?::(.*?))?@)?(.+?)(?::(\d+))?\/(.*?)(?:\/(.*?))?\/?$/
		const matches = options.match(smbUrlRe)
		if(!matches) {
			throw new Error('Invalid smb url')
		}
		_options.domain = matches[1] || _options.domain
		_options.username = matches[2] || _options.username
		_options.password = matches[3] || _options.password
		_options.host = matches[4]
		_options.port = matches[5] || _options.port
		_options.share = matches[6]
		_options.path = matches[7] || ''
	} else {
		Object.assign(_options, options)
	}
	if(!_options.host || !_options.share) {
		throw new Error('Invalid parameters')
	}
	return _options
}

class SMBSession {
	constructor(options) {
		this.options = options
		this.done = false
		this.responsePromse = null
		this.responseBuffer = Buffer.alloc(0)
		this.messageid = 0
		this.sessionid = '0'
		this.treeid = 0
		this.fileid = null

		this.socket = new net.Socket()
			.on('data', data => this._response(data))
			.on('error', err => {
				this.responsePromise.reject(err)
			}).on('end', () => {
				if(!this.done)
					this.responsePromise.reject(new Error('Connection unexpected ended'))
			})
			.connect(options.port, options.host)
	}

	async connect() {
		this.done = false
		let result, data

		// negotiate
		result = await this._request(this._createRequest(NEGOTIATE))
		this._confirmStatus(result.readUInt32LE(12), 0)

		// session setup step 1
		data = ntlm.encodeType1(this.options.host, this.options.domain)
		result = await this._request(this._createRequest(SESSION_SETUP, data))
		this._confirmStatus(result.readUInt32LE(12), 0xC0000016)

		// session setup step 2
		this.sessionid = result.slice(44, 52).toString('hex')
		const nonce = ntlm.decodeType2(result.slice(76))
		const {username, host, domain, password} = this.options
		data = ntlm.encodeType3(username, host, domain, nonce, password)
		result = await this._request(this._createRequest(SESSION_SETUP, data))  
		this._confirmStatus(result.readUInt32LE(12), 0)

		// connect to share
		const path = '\\\\'+host+'\\'+this.options.share
		result = await this._request(this._createRequest(TREE_CONNECT, Buffer.from(path, 'ucs2')))
		this._confirmStatus(result.readUInt32LE(12), 0)
		this.treeid = result.readUInt32LE(40)

		this.done = true
	}

	async enumerate(path) {
		this.done = false
		path = path.replace(/\\/g, '/').split('/').filter(p => p).join('\\')

		// create file handle
		let result, files = []
		result = await this._request(this._createRequest(CREATE, Buffer.from(path, 'ucs2')))
		this._confirmStatus(result.readUInt32LE(12), 0)
		const fileid = result.slice(132, 148).toString('hex')

		// query directory
		let status = 0
		while(status === 0) {
			result = await this._request(
				this._createRequest(QUERY_DIRECTORY, {fid: fileid, buffer: Buffer.from('*', 'ucs2')})
			)
			status = result.readUInt32LE(12)
			if(status === 0) {
				const dataLength = result.readUInt32LE(72)
				const data = result.slice(76, 76 + dataLength)
				files = files.concat(this._parseFiles(data))
			}
		}
		this._confirmStatus(status, 0x80000006) // STATUS_NO_MORE_FILES

		// filter '.' and '..' files
		files = files.filter(f => !['.', '..'].includes(f.filename))

		// close file handle
		await this._request(this._createRequest(CLOSE, fileid))

		this.done = true
		return files
	}

	async close() {
		this.socket.destroy()
	}

	/* PRIVATE FUNCTIONS */

	_request(message) {
		const promise = new Promise((resolve, reject) => this.responsePromise = {resolve, reject})
		this.socket.write(message)
		this.messageid++
		return promise
	}

	_response(data) {
		this.responseBuffer = Buffer.concat([this.responseBuffer, data])
		const netbiosLength = this.responseBuffer.readUInt32BE(0)
		// check if packet has been received completely
		if(this.responseBuffer.length >= netbiosLength + 4) {
			const packetBuffer = Buffer.from(this.responseBuffer.slice(0, netbiosLength + 4))
			this.responseBuffer = this.responseBuffer.slice(netbiosLength + 4)
			this.responsePromise.resolve(packetBuffer)
		}
	}

	_createRequest(command, params) {
		const header = Buffer.from(NETBIOS_HEADER + SMB_HEADER, 'hex')
		let structure = Buffer.from(REQUEST_STRUCTURES[command], 'hex')

		if(command === SESSION_SETUP) {
			structure.writeInt32LE(params.length, 14)
			structure = Buffer.concat([structure, params])
		} else if(command === TREE_CONNECT) {
			structure.writeUInt16LE(params.length, 6)
			structure = Buffer.concat([structure, params])
		} else if(command === CREATE) {
			structure.writeUInt16LE(params.length, 46)
			// we must write at least one byte
			if(params.length)
				structure = Buffer.concat([structure, params])
			else
				structure = Buffer.concat([structure, Buffer.from([0])])
		} else if(command === CLOSE) {
			structure.write(params, 8, 16, 'hex')
		} else if(command === QUERY_DIRECTORY) {
			structure.write(params.fid, 8, 16, 'hex')
			structure.writeUInt16LE(params.buffer.length, 26)
			structure = Buffer.concat([structure, params.buffer])
		}
		
		const buffer = Buffer.concat([header, structure])
		// write headers
		buffer.writeUInt16LE(command, 16)
		buffer.writeUInt32LE(this.messageid, 28)
		buffer.writeUInt32LE(this.treeid, 40)
		buffer.write(this.sessionid, 44, 8, 'hex')
		buffer.writeUInt32BE(buffer.length - 4, 0)
		return buffer
	}

	_confirmStatus(status, expected) {
		if(status !== expected) {
			if(COMMON_ERRORS[status]) {
				throw new Error(COMMON_ERRORS[status])
			} else {
				throw new Error(`NTSTATUS 0x${status.toString(16)}. Expected: 0x${expected.toString(16)}`)
			}
		}
	}

	_parseFiles(data) {
		let files = [], offset = 0, nextEntryOffset = -1

		const LDAPtoUNIXtime = time => new Date(time/1e4 - 1.16444736e13)
		const readUInt64LE = (buf, offset) =>
			parseInt(buf.slice(offset, offset + 8).swap64().toString('hex'), 16)

		while(nextEntryOffset !== 0) {
			nextEntryOffset = data.readUInt32LE(offset)

			const fileNameLength = data.readUInt32LE(offset + 60)
			const fileAttributes = data.readUInt32LE(offset + 56)
			const file = {
				filename: data.toString('ucs2', offset + 104, offset + 104 + fileNameLength),
				size: readUInt64LE(data, offset + 40),
				sizeOnDisk: readUInt64LE(data, offset + 48),
				created: LDAPtoUNIXtime(readUInt64LE(data, offset + 8)),
				accessed: LDAPtoUNIXtime(readUInt64LE(data, offset + 16)),
				modified: LDAPtoUNIXtime(readUInt64LE(data, offset + 24)),
				changed: LDAPtoUNIXtime(readUInt64LE(data, offset + 32)),
				attributes: fileAttributes,
				directory: !!(fileAttributes & 0x10),
				hidden: !!(fileAttributes & 0x02)
			}
			files.push(file)
			offset += nextEntryOffset
		}
		return files
	}
}
