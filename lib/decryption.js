const Algorithm = require('./algo')
const auth = require('./auth')
const fetch = require('node-fetch')
const forge = require('node-forge')
const struct = require('python-struct')

module.exports = class Decryption {
  constructor(params) {
    // Client's API key
    // Identifies the client to the server
    this.papi = params.access_key_id
    // Client's secret API key
    // Authenticates HTTP requests
    this.sapi = params.secret_signing_key
    // Client's secret RSA encryption key/password
    this.srsa = params.secret_crypto_access_key

    this.host = params.host
    this.endpoint_base = params.host + '/api/v0'
    this.endpoint = '/api/v0/decryption/key'
    this.decryption_started = false
    this.decryption_ready = true
  }

  begin() {
    if(!this.decryption_ready) {
      console.log('Decryption is not ready')
      return;
    }

    if(this.decryption_started) {
      console.log('Decryption already in progress')
      return;
    }

    // Start the decryption process
    this.decryption_started = true

    this.data = Buffer.from('')
    return this.data
  }

  async update(data) {
    if(!this.decryption_started) {
      console.log('Decryption is not started')
      return;
    }

    // Create and append incoming data into an internal buffer
    let arr = [this.data, data]
    this.data = Buffer.concat(arr)

    if(typeof this.key != 'undefined') {
      return this.update_cipher(data)
    }

    if(typeof this.key == 'undefined' || typeof this.dec == 'undefined') {
      let struct_length = struct.sizeOf('!BBBBH')

      if(this.data.length > struct.length) {
        let structured_string = this.data.slice(0, struct_length)

        let struct_buf = new Buffer.from(structured_string, "binary")

        let arr = struct.unpack('!BBBBH', struct_buf)

        let version = arr[0]
        let flags = arr[1]
        let algorithm_id = arr[2]
        let iv_length = arr[3]
        let key_length = arr[4]

        // Verify version is 0 and flags are correct
        if((version != 0) || (flags & ~Algorithm.CRYPTOFLAG) != 0) {
          return;
        }

        // Does the buffer contains the entire header
        if(this.data.length > struct_length + iv_length + key_length) {
          // Extract the iv
          this.iv = this.data.slice(struct_length, struct_length + iv_length)
          // Extract the encrypted key
          let encrypted_key = this.data.slice(struct_length + iv_length, key_length + struct_length + iv_length)

          let encoded_key = forge.util.encode64(encrypted_key.toString('binary'))

          // Shrink the data
          this.data = this.data.slice(key_length + struct_length + iv_length, this.data.length)

          var md = forge.md.sha512.create()
          md.update(encoded_key)

          let client_id = md.digest().data
          // If key doesn't exist
          if (typeof this.key == "undefined") {
            let url = this.endpoint_base + '/decryption/key'
            let query = { encrypted_data_key: encoded_key }
            let headers = auth.headers(this.papi, this.sapi, this.endpoint, query, this.host, 'post')

            let otherParam = {
              headers: headers,
              body: JSON.stringify(query),
              method: 'POST'
            }

            const response = await fetch(url, otherParam)
            if(response.status == 200) {
              let data = await response.json()
              this.set_key(data, client_id, algorithm_id)
              if((flags & Algorithm.CRYPTOFLAG) != 0) {
                this.dec.setAAD(Buffer.concat([struct_buf, this.iv, encrypted_key]))
              }
              return this.update_cipher(this.data)
            }
            else {
              console.log(`HTTPError Response: Expected 200, got ${response.status}`)
              return;
            }
          }
        }
      }
    }
  }

  set_key(response, client_id, algorithm_id) {
    this.key = {}
    this.key['finger_print'] = response['key_fingerprint']
    this.key['client_id'] = client_id
    this.key['session'] = response['encryption_session']
    this.key['algorithm'] = new Algorithm().findAlgo(algorithm_id)
    this.key['uses'] = 0

    let encrypted_private_key = response['encrypted_private_key']
    // Get wrapped data key from response body
    let wrapped_data_key = response['wrapped_data_key']

    let wdk = forge.util.decode64(wrapped_data_key)
    // Decrypt the encryped private key using @srsa supplied

    let privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa);

    var decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');

    this.key['raw'] = decrypted

    if(typeof this.key != "undefined"){
      this.dec = new Algorithm().decryptor(this.key['algorithm'], this.key['raw'], this.iv)
      this.key['uses'] = this.key['uses'] + 1;
    }
  }

  end() {
    if(!this.decryption_started){
      console.log('Decryption is not Started')
      return;
    }

    this.dec.setAuthTag(this.data)
    this.dec.final('binary')

    // Finish the decryption
    this.decryption_started = false
    return ''
  }

  async update_cipher(data) {
    let tag_length = this.key['algorithm']['tag_length']
    let size = this.data.length - tag_length
    // console.log('***** DECRYPTING *****')
    if(size > 0){
      let cipher_data = this.data.slice(0, size)
      let res = this.dec.update(cipher_data, 'binary', 'binary')
      this.decryption_started = true
      this.data = this.data.slice(size, this.data.length)
      return res
    }
  }

  async close() {
    if(this.decryption_started){
      console.log('Decryption currently running')
      return;
    }

    if(this.key){
      if(this.key['uses'] > 0){
        let query_url = `${this.endpoint}/${this.key['finger_print']}/${this.key['session']}`
        let url = `${this.endpoint_base}/decryption/key/${this.key['finger_print']}/${this.key['session']}`
        let query = {uses: this.key['uses']}
        let headers = auth.headers(this.papi, this.sapi, query_url, query, this.host, 'patch')
        let otherParam = {
          headers: headers,
          body: JSON.stringify(query),
          method: 'PATCH'
        }

        const response = await fetch(url, otherParam)
        if(response.status == 204){
          delete this.data
          delete this.key
          return ''
        }
        // For any other response status code
        else{
          console.log(`HTTPError Response: Expected 204, got ${response.status}`)
          // Exit the function
          return;
        }
      }
    }
  }
}