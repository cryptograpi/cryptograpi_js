// When communicating over the Internet using the HTTP protocol, 
// it is often desirable to be able to securely verify the sender 
// of a message as well as ensure that the message was not tampered 
// with during transit. 
// This class implements a way to add origin authentication and 
// message integrity to HTTP messages. 

const forge = require('node-forge');

// Appends 0 to numbers less than 10
function formatNo(number) {
  if (number<10) {
    return '0' + number
  } else {
    return number
  }
}

// Returns datetime in GMT TZ DAYMONTHYEAR format
const getDate = function() {
  const monthNames = ["January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"];
  const dayNames = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  gmt_time = new Date().toLocaleString("en-US", {timeZone: "GMT"});
  gmt_date = new Date(gmt_time);
  let month = monthNames[gmt_date.getMonth()].substring(0, 3);
  let day = dayNames[gmt_date.getDay()].substring(0, 3);
  let date = `
    ${day}, 
    ${formatNo(gmt_date.getDate())} 
    ${month} 
    ${gmt_date.getFullYEar()} 
    ${formatNo(gmt_date.getHours())}:
    ${formatNo(gmt_date.getMinutes())}:
    ${formatNo(gmt_date.getSeconds())} 
    GMT
  `
}

const auth = {
  headers: function(papi, sapi, endpoint, query, host, http_method) {
    const Package = require('../package.json')

    let req = `${http_method} ${endpoint}`
    let date = new Date()
    let created = parseInt(date.getTime() / 1000)
    // Create de body digest
    var md = forge.md.sha512.create()
    let parsed = JSON.stringify(query)
    md.update(parsed)
    // Finish the digest
    let sha = forge.util.encode64(md.digest().data)
    let digest = 'SHA-512=' + sha
    let all_headers = {}
    all_headers['user-agent'] = 'cryptograpi-js/' + Package.version
    all_headers['content-type'] = 'application/json'
    all_headers['(request-target)'] = req
    all_headers['date'] = getDate()
    let url = new URL(host)
    all_headers['host'] = url.host
    all_headers['(created)'] = created
    all_headers['digest'] = digest
    let headers = ['content-type', 'date', 'host', '(created)', '(request-target)', 'digest']
    var hmac = forge.hmac.create()
    hmac.start('sha-512', sapi)
    
    for (var i = 0; i < headers.length; i++) {
      hmac.update(`${headers[i]}: ${all_headers[headers[i]]}\n`)
    }

    delete all_headers['(created)']
    delete all_headers['(request-target']
    delete all_headers['host']

    all_headers['signature']  = 'keyId="' + papi + '"'
    all_headers['signature'] += ', algorithm="hmac-sha512"'
    all_headers['signature'] += ', created=' + created
    all_headers['signature'] += ', headers="' + headers.join(" ") + '"'
    all_headers['signature'] += ', signature="'
    all_headers['signature'] += forge.util.encode64(hmac.digest().data)
    all_headers['signature'] += '"'

    return all_headers
  }
}

module.exports = auth
