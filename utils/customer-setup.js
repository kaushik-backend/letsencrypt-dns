const acmeClient = require("acme-client");
const crypto = require("crypto");
const AWS = require("aws-sdk");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
require("dotenv").config();

const CERTS_DIR = path.join(__dirname, "..", "certs");
const ACCOUNT_KEY_PATH = path.join(
  __dirname,
  "..",
  process.env.LETS_ENCRYPT_ACCOUNT_KEY || "account.key"
);

// Create the Let's Encrypt account key
const createAccountKey = async () => {
  let accountKey;

  if (fs.existsSync(ACCOUNT_KEY_PATH)) {
    accountKey = fs.readFileSync(ACCOUNT_KEY_PATH, "utf8");
  } else {
    accountKey = acmeClient.forge.createPrivateKey();
    fs.writeFileSync(ACCOUNT_KEY_PATH, accountKey);
  }
  return accountKey;
};

// Function to create an ACME client
const createAcmeClient = async () => {
  const accountKey = await createAccountKey();
  return new acmeClient.Client({
    directoryUrl: acmeClient.directory.letsencrypt.production,
    accountKey,
  });
};

// Wait for DNS TXT record to propagate

async function waitForDNSRecord(recordName, expectedValue, timeout = 180000) {
  const resolvers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"];
  const start = Date.now();
  let retryCount =0 ;

  while (Date.now() - start < timeout) {
    let allMatch = true;

    for (const resolver of resolvers) {
      try {
        const customResolver = new dns.Resolver();
        customResolver.setServers([resolver]);
        const records = await customResolver.resolveTxt(recordName);
        const flatRecords = records.flat().map((r) => r.replace(/"/g, ""));

        if (flatRecords.includes(expectedValue)) {
          console.log(` ${resolver} sees ${recordName} -> ${expectedValue}`);
        } else {
          console.log(
            ` ${resolver} does NOT have expected value for ${recordName}:`,
            flatRecords
          );
          allMatch = false;
        }
      } catch (err) {
        console.log(`⚠️  Failed to query ${resolver}: ${err.message}`);
        allMatch = false;
      }
    }

    if (allMatch) {
      console.log(`DNS record found globally: ${recordName}`);
      return;
    }
    
     // Retry logic after waiting 30 seconds
    if (retryCount < maxRetries) {
      retryCount++;
      console.log(`Attempt ${retryCount} failed. Retrying...`);
      await new Promise((res) => setTimeout(res, 30000)); // Wait for 30 seconds before retrying
    } else {
      // Max retries exceeded
      console.log(`Max retries exceeded for DNS propagation check.`);
      break;
    }
  }

  throw new Error(`DNS record ${recordName} did not propagate in time`);
}

// Create DNS TXT record for validation
const createDNSRecord = async (client, challenge, identifier) => {
  // Get the correct DNS-01 TXT value from acme-client

 // Get key authorization from the client
  const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);
  console.log("keyAuthorization",keyAuthorization)

  // Use the proper method to get the DNS-01 challenge value
 // Calculate DNS-01 value manually (RFC-8555)
  const dnsValue = `${challenge.token}.${keyAuthorization}`;
  console.log("====dns-value=====",dnsValue);
  const baseDomain = process.env.DOMAIN;
  let recordName = `_acme-challenge.${identifier}`;

  // Adjust for manual entry in GoDaddy / other providers
  // if (
  //   (!process.env.DNS_PROVIDER || process.env.DNS_PROVIDER.toLowerCase() !== "route53") &&
  //   baseDomain &&
  //   recordName.endsWith(`.${baseDomain}`)
  // ) {
  //   recordName = recordName.replace(`.${baseDomain}`, "");
  // }

  const dnsData = {
    Type: "TXT",
    Name: `_acme-challenge.${identifier}`,
    TTL: 600,
    ResourceRecords: [{ Value: dnsValue }]
    // ResourceRecords: [{ Value: `"${dnsValue}"` }],
  };

  console.log("\n==== DNS RECORD ====");
  console.log(dnsData);

  // Automatic DNS (Route 53)
  if (
    process.env.DNS_PROVIDER === "Route53" &&
    process.env.AWS_ACCESS_KEY_ID &&
    process.env.AWS_SECRET_ACCESS_KEY &&
    process.env.ROUTE53_HOSTED_ZONE_ID
  ) {
    const route53 = new AWS.Route53();
    await route53.changeResourceRecordSets({
      HostedZoneId: process.env.ROUTE53_HOSTED_ZONE_ID,
      ChangeBatch: {
        Changes: [{ Action: "UPSERT", ResourceRecordSet: dnsData }],
      },
    }).promise();
    console.log(`Route53 DNS record created`);
  } else {
    console.log("⚠️ No AWS credentials — please create the above TXT record manually.");
  }

  return dnsValue;
};


// Request SSL certificate from Let's Encrypt
const requestCertificate = async (subdomain) => {
  try {
    const client = await createAcmeClient();

    // 1. Create account with Let's Encrypt
    await client.createAccount({
      contact: [`mailto:${process.env.LETS_ENCRYPT_EMAIL}`],
      termsOfServiceAgreed: true,
    });

    // 2. Build full domain
    const DomainName = `${subdomain}.${process.env.DOMAIN}`;
    console.log(`\n Requesting certificate for: ${DomainName}`);

    // 3. Create order
    const order = await client.createOrder({
      identifiers: [{ type: "dns", value: DomainName }],
    });

    // 4. Get authorization(s)
    const authorizations = await client.getAuthorizations(order);
    console.log("===authorizations=======",authorizations);
    const authz = authorizations[0]; 
    console.log("===authZ====",authz);
    const identifier = authz.identifier.value;
   
    // 5. Find DNS-01 challenge
    const challenge = authz.challenges.find(
      (chal) => chal.type === "dns-01"
    );
    console.log("========challenge=========",challenge);
    if (!challenge) {
      throw new Error("No DNS-01 challenge found");
    }
    console.log(`🔍 Challenge token: ${challenge.token}`);

    // 6. Create DNS TXT record
    const dnsValue = await createDNSRecord(client, challenge, identifier);

    // 7. Wait for DNS propagation if not using Route53
    const isAuto =
      process.env.DNS_PROVIDER === "Route53" &&
      process.env.AWS_ACCESS_KEY_ID &&
      process.env.AWS_SECRET_ACCESS_KEY &&
      process.env.ROUTE53_HOSTED_ZONE_ID;

    const dnsRecordName = `_acme-challenge.${identifier}`;
    console.log(`\n📝 Expected DNS name: ${dnsRecordName}`);
    console.log(`📝 Expected TXT value: ${dnsValue}`);

    if (!isAuto) {
      console.log("\ Waiting for DNS record to propagate globally...");
      await waitForDNSRecord(dnsRecordName, dnsValue);
    }

    // 8. Tell ACME to verify the challenge
    console.log("\n Asking Let's Encrypt to verify challenge...");
    await client.verifyChallenge(authz, challenge);

    // 9. Wait for validation
    console.log("============validating============")
    await client.waitForValidStatus(challenge);
    console.log(" DNS challenge validated successfully!");

    // 10. Create CSR & finalize order
    const [csr, privateKey] = await acmeClient.forge.createCsr({
      commonName: DomainName,
    });
    const cert = await client.finalizeOrder(order, csr);

    console.log(" Certificate issued successfully!");
    saveCertificateFiles(DomainName, cert, privateKey);

    return { cert, privateKey };

  } catch (error) {
    console.error("Error in certificate request:", error);
    throw error;
  }
};

// Save cert and key to files
const saveCertificateFiles = (domainName, cert, privateKey) => {
  if (!fs.existsSync(CERTS_DIR)) {
    fs.mkdirSync(CERTS_DIR, { recursive: true });
  }

  const certPath = path.join(CERTS_DIR, `${domainName}.crt`);
  const keyPath = path.join(CERTS_DIR, `${domainName}.key`);

  fs.writeFileSync(certPath, cert);
  fs.writeFileSync(keyPath, privateKey);

  console.log(`Certificate saved: ${certPath}`);
  console.log(`Private key saved: ${keyPath}`);
};

//  Deploy certificate without downtime
const deployCertificateWithZeroDowntime = (domain, cert, key) => {
  if (!fs.existsSync(CERTS_DIR)) fs.mkdirSync(CERTS_DIR, { recursive: true });
  const certPath = path.join(CERTS_DIR, `${domain}.crt`);
  const keyPath = path.join(CERTS_DIR, `${domain}.key`);

  fs.writeFileSync(certPath, cert);
  fs.writeFileSync(keyPath, key);

  // reload Nginx
  require("child_process").execSync("nginx -s reload");

  return { certPath, keyPath };
};

module.exports = {
  requestCertificate,
  createDNSRecord,
  deployCertificateWithZeroDowntime,
};
