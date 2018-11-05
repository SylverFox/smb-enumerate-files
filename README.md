# smb-enumerate-files
> Enumeration of files on SMB shares for Node.js

This package allows easy file enumeration of SMB shared folders on a host machine. Useful to index or monitor an external machine. The implementation is focused on efficiency, both in time and network overhead.

## Install
```
$ npm install smb-enumerate-files
```

## Usage
### `enumerate(options)`
Connects to an SMB share and retrieves the directory listing of the specified path. The options parameter take the following properties:

- `host` **(required)** - The remote smb server's hostname or ip address
- `share` **(required)** - The share to connect to on the host machine
- `path` *(optional)* - The path on the share to retrieve the enumeration from. When omitted, the root directory of the share will be used. Slashes and backslashes can be used interchangeably.
- `port` (optional) - The port to connect to. Defaults to *445*.
- `username` (optional) - The username of an account on the server. Defaults to *guest*
- `password` (optional) - The password of the account. Defaults to *empty*
- `domain` (optional) - The SMB NT domain. Defaults to *WORKGROUP*

Instead, an SMB connection url string may be used of the following format:

`smb://[[<domain>;]<username>[:<password>]@]<host>[:port]/share[/path/to/folder][/]`

This returns a **promise** resolving in an **array** of files. Each entry has the following properties:

- `filename` - The name of the file
- `size` - The entry's file size
- `sizeOnDisk` - The file's allocation size on the remote drive
- `created` - A js Date object with the time the file was created
- `accessed` - A js Date object with the time the file was last accessed
- `modified` - A js Date object with the time the contents of the file were last modified. This excludes attribute or meta information changes
- `changed` - A js Date object with the time the file was last changed, including meta information and attributes
- `attributes` - The combined attributes of the file. See the [specification](https://msdn.microsoft.com/en-us/library/cc232110.aspx) for all possible attributes.
- `directory` - A boolean specifying whether this entry is a directory
- `hidden` - A boolean specifying is this file is marked as hidden

### Example
```js
const smbEnumFiles = require('smb-enumerate-files') 

smbEnumFiles.enumerate({
  host: 'myserver',
  share: 'myshare',
  path: 'path/to/folder'
}).then(files => {
  // do something with these files
}).catch(err => console.log(err))

// or in an async function
const files = await smbEnumFiles.enumerate('smb://myserver/myshare/path/')
```

### `createSession(options)`
Creates a session based on the given options. You would use this method rather than the above when you need to enumerate multiple paths because it does not close the session automatically after retrieval.

The options are the same as the above `enumerate` function. However, the `path` argument is ignored.

#### `session.connect()`
Connects this session. **Must** be called before other function can be used. Returns a promise that resolves when the client has successfully connected to the server

#### `session.enumerate(path)`
Retrieves the directory listing of the specified path. The `path` option must be a string with a relative path from the share. Leading and/or trailing slashes are allowed and slashes and backslashes can be interchangeably used. Returns a promise equal to the `enumerate` function above.

#### `session.close()`
Closes the session.

### Example
```js
const smbEnumFiles = require('smb-enumerate-files')

const paths = ['', '/path/to/folder/', 'otherpath']

const session = smbEnumfiles.createSession('smb://admin:hunter2@myserver/myshare')
await session.connect()
for(let path of paths) {
  const files = await session.enumerate(path)
  // do something with these files
}
session.close()
```

## Bugs & Issues

This package is designed to be small and efficient, which means it does not have proper network package parsing. Problems may occur in non-typical situations. Please report issues in the issue tracker to improve this project.
