const elliptic = require('elliptic');
const fs = require('fs');
const hash = require('hash.js');
const http = require('http');
const addressCodec = require('ripple-address-codec');
// const curve = elliptic.curves['secp256k1'];
// const ecdsa = new elliptic.ec(curve);
const kp = require('ripple-keypairs');
const Ed25519 = elliptic.eddsa('ed25519')

var createHash = require('create-hash');
var apiFactory = require('x-address-codec');

var ACCOUNT_PUBLIC = 35;
var ACCOUNT_PRIVATE = 34;

var api = apiFactory({
  sha256: function(bytes) {
    return createHash('sha256').update(new Buffer(bytes)).digest();
  },
  defaultAlphabet: 'ripple',
  codecMethods: {
    AccountPublic: {version: ACCOUNT_PUBLIC, expectedLength: 33},
    AccountPrivate: {version: ACCOUNT_PRIVATE, expectedLength: 32}}
});

const sfSequence = '$'
const sfPublicKey = 'q'
const sfSigningPubKey = 's'
const sfSignature = 'v'

// const masterKey = 'nHUVPyHw6um1tbDeSQoKGh3JqEZKnDinwepAN9j5XaMW9nypVn6k'
// const masterSecret = 'paVERMWEVgiY1DNULQovgZnb93FxAuRT3YBNoRyRdkjRYCNoD46'

//aKEKiic24cH5kmyhmHLhT6FNGPSLpbtkYJU4f42LHdfC4NxQc3pX
const masterKey = 'nHBuijaH9X1kA91gtkZotV9FXMpmBCzCQUqTUU9CiGqgPvWaHgbU'
const masterSecret = 'pn8mz5cceut1Eb5AhnFv9bxRNyQgUirgSTQbz7zquPs5zzwcVbA'


const seed = 'shpSdwJbM4HwrX9SeZUoaWx4D1afN';
const signingPubKey = 
  'n9KJYeLSD2TXaJW2amtA4VnqCDPWhzBtbyQLcsz6peFMyxUMMsg6';
  //aBQirWKK37DmRVroC4rwViGRLF838MNizB3ucBWj5mDXQJN8g6jC



const sequence = 1
var sequence_buf = new Buffer(4)
sequence_buf.writeUInt32BE(sequence)
const sequence_bytes = sequence_buf.toJSON().data

var master_public_bytes = addressCodec.decodeNodePublic(masterKey)
const ephemeral_public_bytes = addressCodec.decodeNodePublic(signingPubKey)

manifest = [].concat(new Buffer(sfSequence).toJSON().data,
                     sequence_bytes,
                     new Buffer(sfPublicKey).toJSON().data,
                     [master_public_bytes.length],
                     master_public_bytes,
                     new Buffer(sfSigningPubKey).toJSON().data,
                     [ephemeral_public_bytes.length],
                     ephemeral_public_bytes)

var digest = new Buffer('MAN\0').toJSON().data
digest = digest.concat(manifest)

const master_secret_bytes = addressCodec.decodeNodePrivate(masterSecret)
// const master_secret_bytes = addressCodec.decode(masterSecret, {version:34, expectedLength: 32})
const manSig = Ed25519.sign (digest, master_secret_bytes).toBytes()


master_public_bytes.shift()
if (!Ed25519.verify(digest, manSig, master_public_bytes)) {
  throw new Error('Manifest has invalid signature')
}

manifest = manifest.concat(new Buffer(sfSignature).toJSON().data,
                           [manSig.length],
                           manSig)

console.log(Buffer.from(manifest).toString('base64'))

// const signingKeyBytes =
//   addressCodec.decodeSeed(signingKey);
const signingKeys = kp.deriveKeypair(seed, {validator:true});

// console.log(signingPubKey)
// console.log(addressCodec.encodeNodePublic(signingKeys.publicKey))
const signingPubKeyBytes =
  addressCodec.decodeNodePublic(signingPubKey);

// console.log(kp.deriveAddress(signingKeys.publicKey))

const list = {
  sequence: 1,
  validators: [
    // { validation_public_key: 'n949f75evCHwgyP4fPVgaHqNHxUVN15PsJEZ3B3HnXPcPjcZAoy7'},
    // { validation_public_key: 'n9MD5h24qrQqiyBC8aeqqCWvpiBiYQ3jxSr91uiDvmrkyHRdYLUj'},
    // { validation_public_key: 'n9L81uNCaPgtUJfaHh89gmdvXKAmSt5Gdsw2g1iPWaPkAHW5Nm4C'},
    // { validation_public_key: 'n9KiYM9CgngLvtRCQHZwgC2gjpdaZcCcbt3VboxiNFcKuwFVujzS'},
    // { validation_public_key: 'n9LdgEtkmGB9E2h3K4Vp7iGUaKuq23Zr32ehxiU8FWY7xoxbWTSA'}
    // { validation_public_key: 'n9KFpzois2Xz1jpAS3tgc641N5nAYCqdjBowj9xDLupVbUKgYBdh'},
    // { validation_public_key: 'n9M4GA26XHUCPGFGjiBe9HstukNEzJMHkotrZb5B4yJrV1XETmMu'},
    // { validation_public_key: 'n9MqxBfZtNwguwfrn6VxNz2uGdB9M8wYaF5MxNEsNNu1rqTtWQEC'},
    // { validation_public_key: 'n9MoDiDVjbn5TVwbSnvBKH2RBc2LsNmeRrH5gCGgu8itVFECCHq4'},
    // { validation_public_key: 'n94EQCDERH6B3YExX6ag4f1xopjeVcDuVHTNotZ8u6Gm2iuk7tcp'},
    // { validation_public_key: 'n9MSLSZuMB5ncyYabfcDBq1A8cNqFjXyL1Rc2R4s8Au7oF6JU8Fp'},
    // { validation_public_key: 'n9Jm4jwB7PhgLR8hskGVXJNSCLviJRjwawLuJuXdtmDrv5UGd6AK'},
    // { validation_public_key: 'n9LkU6Bb3YT4WyPMhBpT5MnhrXkc4yAvdXKKHWvP9ZH3JQc9G6CR'},
    // { validation_public_key: 'n94Pq81fKBAYoeezNb8TxqPKmfdscCam5EgJpccHGFe6kq3TagB8'},
    // { validation_public_key: 'n9MsoiBQsxKZDZvV9FF9awnHp5U8bZxtxQwyS9jkC3UeXL1y9pmw'},
    // { validation_public_key: 'n9MqNHw7MnydTaeWYzmCyS6CsSAcGivHUm9G7HfMUFN5tAiDBAfK'},
    // { validation_public_key: 'n94E3AmcYGPt9jesQmztj5YTJfg5sEm9u9Rmhxdgqu4cwup96FJw'},
    // { validation_public_key: 'n94w8sAuX7F7EJVQQfsjXNQuW2iWqbXJmj4PRmcFLJUiMzwpPuRT'},
    // { validation_public_key: 'n9M33tUDSFqq4nzjVzn8kyFPXJTmjd82GASdkqKUEkZYfvbeTHsQ'},
    // { validation_public_key: 'n94wb1e2xoebNkqpnj2aWdZKEZCSYdn6UJospgYKugZaR1MNCx9s'},
    // { validation_public_key: 'n9J22n8pkjmFQ6YBynvPWRpbz2bkXchMvK9qjPdeabDjEMYjbaGj'},
    // { validation_public_key: 'n9JoHKBueEPYmVGxCgRMyaxJzfxRPnPqcmdmCyrfc1PRjZhLxvd5'},
    // { validation_public_key: 'n9Lz6ftbRiySuVLt6UvEj1oTq8XZXRb3EQpzMBYN9m2bkLoLysuY'},
    // { validation_public_key: 'n9MNqUKBrE45GSTxZdnHJ6sriuRArND2J3sQpmtCiBS7zfuHy7UU'},
    // { validation_public_key: 'n9Mm4rKyh1cdM4Bqy7cUDivuoYtTKiY9VDNNZKtnRJbFzxWUWf38'}
    {
      validation_public_key: 'nHUhG1PgAG8H8myUENypM35JgfqXAKNQvRVVAFDRzJrny5eZN8d5',
      manifest: 'JAAAAAVxIe1cuaXkpIJWKA7fDkF8oZ2GaW3nM1ygyTGjachtr1+0aHMhA03VbFqthVuu64OLAIivdagP4O62lpsXThg4mPorUYQRdkDM0Yr2wkmK+SoRDn2pDzZffPhsRboH26gXQSnKHRQSGTtOrkxSViHP1c8i3uELvgwFZ5jvQI4fsiHM81kv8ZgO'
    },
    {
      validation_public_key: 'nHUPDdcdb2Y5DZAJne4c2iabFuAP3F34xZUgYQT2NH7qfkdapgnz',
      manifest: 'JAAAAAdxIe2HvYIhFRpT/lK7+aSpNjF6jxE/AhKZGqFXICXML972FHMhAp9jGs5XyuwqgjdMi8umZetX041B6f+b4o289ApzFsY+dkBqulfVUwCuze3usEvsmn72iGOSnuncUTWrpidaRKZLfoxlpiuvpPKcTCM1a5iUDQ/Dcm18OPT3WsXV04OZ+HwI'
    }
  ]
}

var blob_buf = Buffer.from(JSON.stringify(list));

// console.log(blob)
// console.log('')
// const signature = kp.sign(blob, signingKeys.privateKey);
console.log(signingKeys)
console.log('')
const signature = kp.sign(blob_buf.toString('hex'), signingKeys.privateKey);
console.log(signature);
console.log(kp.verify(blob_buf.toString('hex'), signature, signingKeys.publicKey))

const resp = {
  manifest: Buffer.from(manifest).toString('base64'),
  blob: blob_buf.toString('base64'),
  signature: signature,
  version: 1
}
console.log(resp)
http.createServer((req, res) => {
  console.log(req)
  console.log('connect')
  res.writeHead(200, { 'Content-Type': 'application/json' });
  // res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(JSON.stringify(resp));
  // res.end();
}).listen(8000);



