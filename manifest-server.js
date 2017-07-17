const addressCodec = require('ripple-address-codec');
const elliptic = require('elliptic');
const Ed25519 = elliptic.eddsa('ed25519')
const fs = require('fs');
const hash = require('hash.js');
const http = require('http');
const kp = require('ripple-keypairs');

//aKEKiic24cH5kmyhmHLhT6FNGPSLpbtkYJU4f42LHdfC4NxQc3pX
const masterKey = 'nHBuijaH9X1kA91gtkZotV9FXMpmBCzCQUqTUU9CiGqgPvWaHgbU'
const masterSecret = 'pn8mz5cceut1Eb5AhnFv9bxRNyQgUirgSTQbz7zquPs5zzwcVbA'

const seed = 'shpSdwJbM4HwrX9SeZUoaWx4D1afN';
const signingPubKey = 
  'n9KJYeLSD2TXaJW2amtA4VnqCDPWhzBtbyQLcsz6peFMyxUMMsg6';

function makeManifest () {
  const sfSequence = '$'
  const sfPublicKey = 'q'
  const sfSigningPubKey = 's'
  const sfSignature = 'v'

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
  const manSig = Ed25519.sign (digest, master_secret_bytes).toBytes()

  master_public_bytes.shift()
  if (!Ed25519.verify(digest, manSig, master_public_bytes)) {
    throw new Error('Manifest has invalid signature')
  }

  manifest = manifest.concat(new Buffer(sfSignature).toJSON().data,
                             [manSig.length],
                             manSig)

  return Buffer.from(manifest).toString('base64');
}

const list = {
  sequence: 1,
  validators: [
    {
      validation_public_key: 'nHUhG1PgAG8H8myUENypM35JgfqXAKNQvRVVAFDRzJrny5eZN8d5',
      // validation_manifest: 'JAAAAAVxIe1cuaXkpIJWKA7fDkF8oZ2GaW3nM1ygyTGjachtr1+0aHMhA03VbFqthVuu64OLAIivdagP4O62lpsXThg4mPorUYQRdkDM0Yr2wkmK+SoRDn2pDzZffPhsRboH26gXQSnKHRQSGTtOrkxSViHP1c8i3uELvgwFZ5jvQI4fsiHM81kv8ZgO'
      validation_manifest: 'JAAAAAZxIe1cuaXkpIJWKA7fDkF8oZ2GaW3nM1ygyTGjachtr1+0aHMhA03VbFqthVuu64OLAIivdagP4O62lpsXThg4mPorUYQRdkYwRAIgVsDy9fkvjO/7xiUpg5oelqxpvhVJve0th6amoL+Kxm4CIHtBCR5x9+vMXwIX4mNnzTMRrxlEbdoC0GxmtI2rcMo2cBJAdJD+5LuhHzIlEYYb3a9gPQ426LpeKg1sE4sSNlZQqxjjSIv/t2VW7m7A8QOTUoQSODHalidilKKeLAZTUwEjDQ=='
    },
    {
      validation_public_key: 'nHUPDdcdb2Y5DZAJne4c2iabFuAP3F34xZUgYQT2NH7qfkdapgnz',
      // validation_manifest: 'JAAAAAdxIe2HvYIhFRpT/lK7+aSpNjF6jxE/AhKZGqFXICXML972FHMhAp9jGs5XyuwqgjdMi8umZetX041B6f+b4o289ApzFsY+dkBqulfVUwCuze3usEvsmn72iGOSnuncUTWrpidaRKZLfoxlpiuvpPKcTCM1a5iUDQ/Dcm18OPT3WsXV04OZ+HwI'
      validation_manifest: 'JAAAAAhxIe2HvYIhFRpT/lK7+aSpNjF6jxE/AhKZGqFXICXML972FHMhAp9jGs5XyuwqgjdMi8umZetX041B6f+b4o289ApzFsY+dkcwRQIhALMZVp+vlA7jRoxW35o3b5lS1L95EXbbChwxj+BttH+sAiAlzdLXfck66stJWvtGNjDcJ2sk0Zr4/7NPr8T+t/ufhHASQJvxHCWP2oUgdoS6mSV+09LNovtUkGkMBENCL3GVSNNXDYNSRYgOgbRukEFh5CG1PRqdiOOve3qgiqhACT9t/AM='
    },
    {
      validation_public_key: 'nHBu9PTL9dn2GuZtdW4U2WzBwffyX9qsQCd9CNU4Z5YG3PQfViM8',
      // validation_manifest: 'JAAAAANxIe1H/ycCTsaH2sOZ4+tSGYg7LR7sYFfPiB2m/LSnLcGFAnMhAwVANcPA5vTn5rNwYptaHjfHXUrbJCFVtC8io3fG+R0ndkBAdJjwzZZzI6hu/01ir3HBzw4SmHfyNUfxEwoJh4prIcP9To5QAZavwPg6yUotZKfx1leAyaGYcMANPkRjxpEP'
      validation_manifest: 'JAAAAARxIe1H/ycCTsaH2sOZ4+tSGYg7LR7sYFfPiB2m/LSnLcGFAnMhAwVANcPA5vTn5rNwYptaHjfHXUrbJCFVtC8io3fG+R0ndkcwRQIhAOFCBi1i0MG+r8yvIf25hLNVkS1RsgD7nZ6CQpY38wKyAiANf+L4Kyi0Yu3erqevA0phNT3XR9V1S4Pd+DtlJlbUs3ASQNYbRwd86e34XNPTmWr7aXA3HO4uYX9sjEdkcUSOeyTze2C9vsvf6OMvudSyb3ele2W1i8yVPwQGC6TEkMiszAU='
    },
    {
      validation_public_key: 'nHUkAWDR4cB8AgPg7VXMX6et8xRTQb2KJfgv1aBEXozwrawRKgMB',
      // validation_manifest: 'JAAAAARxIe25EAWMZjPOEhaZVhHnqflrgwlvCyj1m0r6lEJH3gf0oHMhAwh6o8GCYR0prxdJa1uNqWO5B0K7yi3KmGijRXWfiULfdkAiTThSva+b3Wlf3CLzuSAQfGHYAJHH2lpoFT/Lxiunn32ODgEl8ENHfseApnEWQe+fjFPZ6s/zEWQVAI5v7yQB'
      validation_manifest: 'JAAAAAVxIe25EAWMZjPOEhaZVhHnqflrgwlvCyj1m0r6lEJH3gf0oHMhAwh6o8GCYR0prxdJa1uNqWO5B0K7yi3KmGijRXWfiULfdkYwRAIgHlK6mS1gfKArr8a2oLcsLtFX6zcKRMGfn2Nl/d3aYq4CICEg3pKbtFjWpny/0jTZLKyud4sj2m0nBop4r63F/+bQcBJA6COj4zoHbeLoMwUQi9jdxRNxu5dR7Bx8rYXR21LyyCgw6WgxpbHrASp7Ex2ZQmNY2qTN7XUrSM99TS9yRgnCAA=='
    },
    {
      validation_public_key: 'nHB1X37qrniVugfQcuBTAjswphC1drx7QjFFojJPZwKHHnt8kU7v',
      // validation_manifest: 'JAAAAANxIe1ETn3WZI/gnC5GjSRLDOQIbG1um36uPI2Ekp1b7Q5E1HMhAo2x9WCHnsVa59/A6AM6OltFhKq0g6SLB15vV3YgfDr6dkBDwdC3N6ReqafsCe1hX7H0UKgN4Wy4tK6VzZdW38AExrfNoQbKu0nSgFb0Kra5v5cOtjInMiUGcYOTOt8TPegD'
      validation_manifest: 'JAAAAAVxIe1ETn3WZI/gnC5GjSRLDOQIbG1um36uPI2Ekp1b7Q5E1HMhAo2x9WCHnsVa59/A6AM6OltFhKq0g6SLB15vV3YgfDr6dkcwRQIhAO6EG5SJJ/wcxuJMaK6oFnWS0i0IxerK84y1oLfoaI/pAiBY3nV8rPfGuj+8r19G0dSfCMyXJ2xd/hS6dkVtxSTbqXASQEiUE0W7Zmh0zJjrAardpOjmApEHezKOeQcvZrsh6/GPy9izA8iG7227/dkTp/4tZsU8XWpPJD0y65xktsH3igA='
    }
  ]
}

var blob_buf = Buffer.from(JSON.stringify(list));

const signature = kp.sign(
  blob_buf.toString('hex'),
  kp.deriveKeypair(seed, {validator:true}).privateKey);

const resp = {
  manifest: makeManifest (),
  blob: blob_buf.toString('base64'),
  signature: signature,
  version: 1
}

http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(JSON.stringify(resp));
}).listen(8000, (err) => {
  if (err)
    console.log(err)
  else
    console.log('server listening on port 8000')
});
