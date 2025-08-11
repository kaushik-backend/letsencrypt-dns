const express = require('express');
const CustomerDomain = require('../models/customerDomain'); 
const User = require('../models/User'); 
const acme = require('acme-client');
const { DNSProvider } = require('../utils/DNSProvider');  
const { Client } = acme;
const authMiddleware = require('../middlewares/authMiddleware');
const router = express.Router();

// Route to create a new customer domain configuration

router.post('/', async (req, res) => {
  try {
    const { companyName, stockSymbol, companyWebsite, subdomain, mappedTo, customerDNSProvider, userId } = req.body;

    // Find the user by ID (ensure the user exists)
    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Create a new customer domain configuration
    const customerDomain = new CustomerDomain({
      companyName,
      stockSymbol,
      companyWebsite,
      subdomain,
      mappedTo,
      customerDNSProvider,
      user: user._id, 
    });
    
    await customerDomain.save();
    
    res.status(201).json({ message: 'Customer domain configuration created successfully', customerDomain });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});



router.post('/request-certificate', async (req, res) => {
  try {
    const { subdomain, userId } = req.body;
    
    // Find customer domain from DB
    const customerDomain = await CustomerDomain.findOne({ subdomain, user: userId });
    if (!customerDomain) {
      return res.status(404).json({ message: 'Customer domain not found' });
    }

    // Setup ACME client with Let's Encrypt Staging server (use production after testing)
    const client = new Client({
      directoryUrl: acme.directory.letsencrypt.staging, // Change to production later
      accountKey: customerDomain.user.accountKey,
    });

    // Create a new private key for Let's Encrypt certificate
    const privateKey = await acme.forge.createPrivateKey();

    // Fetch the authorization object for the domain
    const authorizations = await client.getAuthorizations(customerDomain.subdomain);
    const authorization = authorizations[0];
    const dnsChallenge = authorization.challenges.find(challenge => challenge.type === 'dns-01');

    if (!dnsChallenge) {
      return res.status(400).json({ message: 'No DNS challenge available for this domain' });
    }

    // Extract the DNS challenge details
    const { token, keyAuthorization } = dnsChallenge;
    const { name, type, value } = dnsChallenge;

    // Now, use the DNS provider's API (Route53/Cloudflare) to add the DNS record
    await DNSProvider.addDNSRecord(customerDomain.subdomain, name, type, value);
    
    // Update domain status to dns_validation
    customerDomain.status = 'dns_validation';
    await customerDomain.save();

    // Poll the challenge until it's validated
    await client.answerChallenge(dnsChallenge);
    await client.pollAuthorization(authorization);

    // Once the DNS challenge is validated, request the certificate
    const certificate = await client.getCertificate({ domain: customerDomain.subdomain });

    // Save the certificate and key to the database
    customerDomain.status = 'certificate_issued';
    customerDomain.certificate = certificate.cert;
    customerDomain.privateKey = privateKey;
    await customerDomain.save();

    res.status(200).json({ message: 'Certificate issued successfully', certificate });
  } catch (error) {
    console.error('Error issuing certificate:', error);
    res.status(500).json({ message: 'Error during certificate issuance', error: error.message });
  }
});


// Route to fetch all customer domains
router.get('/', async (req, res) => {
  try {
    const customerDomains = await CustomerDomain.find();
    res.json(customerDomains);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Route to fetch a single customer domain by subdomain
router.get('/:subdomain', async (req, res) => {
  try {
    const customerDomain = await CustomerDomain.findOne({ subdomain: req.params.subdomain });
    if (!customerDomain) {
      return res.status(404).json({ message: 'Customer domain not found' });
    }
    res.json(customerDomain);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Route to update a customer domain's status or DNS configuration (for example, DNS validation)
router.put('/:subdomain', async (req, res) => {
  try {
    const { status, dnsValidation } = req.body;
    
    const updatedCustomerDomain = await CustomerDomain.findOneAndUpdate(
      { subdomain: req.params.subdomain },
      { status, dnsValidation },
      { new: true }
    );
    
    if (!updatedCustomerDomain) {
      return res.status(404).json({ message: 'Customer domain not found' });
    }
    
    res.json({ message: 'Customer domain updated successfully', updatedCustomerDomain });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
