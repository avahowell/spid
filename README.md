# SPID: simple portable intrusion detection

spid is a simple utility used to securely monitor a set of files and directories for changes. Spid databases use the NACL crypto library to provide authenticated encryption of scan history. To use spid, first initialize a database using `spid init`. `spid init` requires that you provide a `config`, which is a JSON object:

```js
{
	"WatchFiles": [
		"/home/foo/bar.zip",
		"/home/foo/bar/baz/"
		"/home/foo/foobar/",
		// etc etc etc
	],
}
```

Create your config.json, then initialize a database (and provide your encryption passphrase):

`spid init -db spid.db -config config.json init`

Now, you can run scans using this database. Any file content changes will be
reflected in a scan and saved to the scan history. Use `spid scan` to run a
scan.

