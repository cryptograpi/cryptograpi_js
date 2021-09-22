const Encryption = require('./lib/encryption.js')
const Decryption = require('./lib/decryption.js')
const {ConfigCredentials, Credentials} = require('./lib/credentials.js')

module.exports = {
  encrypt: async function (params, data) {
    const enc = await new Encryption(params, 1);
    let result = Buffer.concat([enc.begin(), enc.update(data), enc.end()]);
    enc.close();
    return result;
  },

  decrypt: async function (params, data) {
    const dec = new Decryption(params);
    let result = Buffer.concat([dec.begin(), await dec.update(data), dec.end()]);
    dec.close();
    return result;
  },

  Encryption, Decryption, ConfigCredentials, Credentials
}