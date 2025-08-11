const acme = require('acme-client');
const fs = require('fs');
const path = require('path');

const { Client } = acme;
const CERT_DIR = path.resolve(__dirname, 'certs');

const DOMAIN = 'small-sides-laugh.loca.lt';  // Localtunnel URL
const EMAIL = 'kaushik@klizos.com';

async function getCertificate() {
  try {
    const privateKey = await acme.forge.createPrivateKey();
    console.log("=====privateKey========", privateKey);

    // Set up ACME client
    const client = new Client({
      directoryUrl: acme.directory.letsencrypt.staging,  
      accountKey: privateKey,
    });

    // Register the account with Let's Encrypt
    const account = await client.createAccount({
      termsOfServiceAgreed: true,
      contact: [`mailto:${EMAIL}`],
    });

    console.log("Account created:", account);  

    // Request authorization for the domain
    const authorizations = await client.getAuthorizations(DOMAIN);
    console.log("Authorization details:", authorizations);  

    if (!authorizations || authorizations.length === 0) {
      throw new Error("No authorizations found.");
    }

    // Fetch the HTTP-01 challenge from the authorization
    const httpChallenge = authorizations[0].challenges.find(challenge => challenge.type === 'http-01');
    
    if (!httpChallenge) {
      throw new Error("No HTTP challenge found for domain.");
    }

    // Serve the HTTP challenge 
    const token = httpChallenge.token;
    const challengePath = path.join(CERT_DIR, '.well-known/acme-challenge', token);

    fs.mkdirSync(path.dirname(challengePath), { recursive: true });
    fs.writeFileSync(challengePath, httpChallenge.keyAuthorization);

    console.log(`Challenge for ${DOMAIN} is ready. Serve it at: /${token}`);

    // Wait for the challenge to be validated
    await client.answerChallenge(httpChallenge);
    await client.pollAuthorization(authorizations[0]);

    // Create CSR 
    const [certificate, csr] = await acme.forge.createCsr({
      commonName: DOMAIN,
      altNames: [DOMAIN],
    });
    console.log("=====csr======", csr);

    // After the challenge is complete, issue the certificate
    const cert = await client.getCertificate(csr);

    // Save the certificate and private key to files
    if (!fs.existsSync(CERT_DIR)) {
      fs.mkdirSync(CERT_DIR);
    }

    fs.writeFileSync(path.join(CERT_DIR, 'cert.pem'), cert);
    fs.writeFileSync(path.join(CERT_DIR, 'privkey.pem'), privateKey);
    fs.writeFileSync(path.join(CERT_DIR, 'fullchain.pem'), cert + cert);

    console.log('Certificate issued and saved.');
  } catch (err) {
    console.error('Error during certificate issuance:', err);
  }
}

getCertificate();
