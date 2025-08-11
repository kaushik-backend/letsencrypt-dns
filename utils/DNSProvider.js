const axios = require('axios');

class DNSProvider {
  static async addDNSRecord(domain, name, type, value) {
    const apiKey = process.env.GODADDY_API_KEY;
    const secret = process.env.GODADDY_SECRET_KEY;
    
    const url = `https://api.godaddy.com/v1/domains/${domain}/records/${type}/${name}`;
    
    try {
      const response = await axios.put(url, [{
        data: value,
        ttl: 600 // Set TTL for DNS record
      }], {
        headers: {
          'Authorization': `sso-key ${apiKey}:${secret}`
        }
      });
      
      console.log(`DNS record created: ${name} -> ${value}`);
      return response.data;
    } catch (error) {
      console.error('Error adding DNS record:', error);
      throw new Error('DNS record creation failed');
    }
  }
}

module.exports = { DNSProvider };
