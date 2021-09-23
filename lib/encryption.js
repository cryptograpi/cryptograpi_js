const Algorithm = require('./algo')
const auth = require('./auth')
const fetch = require('node-fetch')
const forge = require('node-forge')
const struct = require('python-struct')

module.exports = class Encryption {
  constructor(params, uses) {
    // The client's API key
    this.papi = params.access_key_id
    // The client's secret API key to authenticate HTTP reqs
    this.sapi = params.secret_signing_key
    // Client's secret RSA encryption key/password used to decrypt the
    // client's RSA key from the server.
    // This key is not retained in the object
    this.srsa = params.secret_crypto_access_key
    this.host = params.host
    this.endpoint_base = this.host + '/api/v0'
    this.endpoint = '/api/v0/encryption/key'
    // Build the endpoint URL
    this.url = this.endpoint_base + '/encryption/key'
    // Build the req body counting uses
    let query = { uses: uses }
    // Retrieves the headers for the request using the Auth object
    let headers = auth.headers(this.papi, this.sapi, this.endpoint, query, this.host, 'post')
    
    this.otherParam = {
      headers: headers,
      body: JSON.stringify(query),
      method: 'POST'
    }

    this.encryption_started = false
    this.encryption_ready = true

    // Request a new encryption key from the server.
    // If the request fails, an HTTPError is raised
    return new Promise(async(resolve, reject) => {
      try {
        // Wait for server response
        const response = await fetch(this.url, this.otherParam)
        // If response is Created
        if(response.status == 201) {
          let data = await response.json()
          this.set_key(data)
        } else {
          console.log(`HTTPError Response: Expected 201, got ${response.status}`)
          return;
        }
      } catch(ex) {
        // Reject the promise in case of any exception
        return reject(ex);
      }
      resolve(this);
    });
  }

  set_key(data) {
    // Handles the returned json object from our api server
    this.key = {}
    this.key['id'] = data['key_fingerprint']
    this.key['session'] = data['encryption_session']
    this.key['security_model'] = data['security_model']
    this.key['algorithm'] = data['security_model']['algorithm'].toLowerCase()
    this.key['max_uses'] = data['max_uses']
    this.key['encrypted'] = forge.util.decode64(data['encrypted_data_key'])
    this.key['uses'] = 0
    // Get the encrypted key from body
    let encrypted_private_key = data['encrypted_private_key']
    // Get data(wrapped) from the res body
    let wrapped_data_key = data['wrapped_data_key']
    let wdk = forge.util.decode64(wrapped_data_key)
    // Decrypt the encrypted private key using @srsa
    let privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa)
    var decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');
    this.key['raw'] = decrypted
    // Build the algorithm object
    this.algo = new Algorithm().getAlgo(this.key['algorithm'])
  }

  begin() {}

  update(data) {}

  end() {}

  close() {}
}