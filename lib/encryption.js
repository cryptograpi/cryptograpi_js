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

  begin() {
    // Begin the encryption process
    // A call to begin() starts the `uses` counter and creates
    // an internal context to encrypt the data
    if(!this.encryption_ready) {
      console.log('Not ready to start')
      return;
    }

    if(this.encryption_started) {
      console.log('Encryption alreadyin progress')
      return;
    }

    if(this.key['uses'] > this.key['max_uses']) {
      console.log("Maximum key uses exceeded")
      return;
    }

    this.key['uses'] = this.key['uses'] + 1;

    // Create a new encryption context and IV
    let cipher_values = new Algorithm().encryptor(this.algo, this.key['raw'])
    // get encryption context
    this.enc = cipher_values[0]
    // get IV
    this.iv = cipher_values[1]
    // Pack res into bytes
    let array_buf = struct.pack('!BBBBH', 0, Algorithm.CRYPTOFLAG, this.algo['id'], this.iv.length, this.key['encrypted'].length)

    let string_buf = Buffer.from(this.key['encrypted'], 'binary')

    let buf_arr = [array_buf, this.iv, string_buf]

    var main_buf = Buffer.concat(buf_arr)

    this.enc.setAAD(main_buf)
    this.encryption_started = true
    return main_buf
  }

  update(data) {
    if(!this.encryption_started) {
      console.log('Encryption is not started')
      return;
    }

    let res = this.enc.update(data, 'binary', 'binary')

    let update = Buffer.from(res, 'binary')
    return update
  }

  end() {
    // Finalizes the encryption.
    // Adds any authentication information (if required by the algo)
    if(!this.encryption_started) {
      console.log('Encryption is not started')
      return;
    }

    // Finalize the encryption
    let encrypted = this.enc.final('binary')

    encrypted = Buffer.from(encrypted, 'binary')
    var tag = this.enc.getAuthTag()
    let arr = [encrypted, tag]
    this.encryption_started = false
    return Buffer.concat(arr)
  }

  close() {
    if(this.encryption_started) {
      console.log('Encryption currently running')
      return;
    }

    // Check for usage
    if(this.key['uses'] < this.key['max_uses']) {
      let query_url = `${this.endpoint}/${this.key['id']}/${this.key['session']}`
      // Build the request URL
      let url = `${this.endpoint_base}/encryption/key/${this.key['id']}/${this.key['session']}`
      // Build the actual query
      let query = {actual: this.key['uses'], requested: this.key['max_uses']}
      // Retrieve headers
      let headers = auth.headers(this.papi, this.sapi, query_url, query, this.host, 'patch')
      let otherParam = {
        headers: headers,
        body: JSON.stringify(query),
        method: 'PATCH'
      }

      return new Promise(async(resolve, reject) => {
        try {
          const response = await fetch(url, otherParam)
          if(response.status == 204) {
            delete this.key
          } else {
            console.log(`HTTPError Response: Expected 204, got ${response.status}`)
            return;
          }
        } catch(ex) {
          return reject(ex);
        }
        resolve('');
      });
    }
  }
}
