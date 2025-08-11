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
    // If the account key file already exists, read the key
    accountKey = fs.readFileSync(ACCOUNT_KEY_PATH, "utf8");
  } else {
    // If no key exists, generate a new one
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
const waitForDNSRecord = async (
  recordName,
  expectedValue,
  timeout = 180000
) => {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const records = await dns.resolveTxt(recordName);
      const flatRecords = records.flat().map((r) => r.replace(/"/g, ""));
      if (flatRecords.includes(expectedValue)) {
        console.log(`DNS record found: ${recordName} -> ${expectedValue}`);
        return;
      }
      console.log(`...waiting for ${recordName} to propagate`);
    } catch {
      console.log(`...still no DNS record for ${recordName}`);
    }
    await new Promise((res) => setTimeout(res, 10000)); // wait 10 seconds
  }
  throw new Error(`DNS record ${recordName} did not propagate in time`);
};

// Create DNS TXT record for validation
const createDNSRecord = async (client, challenge, identifier) => {
  // Get key authorization from the client
  const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);

  // Calculate DNS-01 value
  const dnsValue = crypto
    .createHash("sha256")
    .update(keyAuthorization)
    .digest("base64url");

  const dnsData = {
    Type: "TXT",
    Name: `_acme-challenge.${identifier}`,
    TTL: 600,
    ResourceRecords: [{ Value: `"${dnsValue}"` }],
  };

  console.log("\n==== DNS RECORD NEEDED ====");
  console.log(dnsData);

  // automatic mode (Route 53)
  if (
    process.env.DNS_PROVIDER === "Route53" &&
    process.env.AWS_ACCESS_KEY_ID &&
    process.env.AWS_SECRET_ACCESS_KEY &&
    process.env.ROUTE53_HOSTED_ZONE_ID
  ) {
    const route53 = new AWS.Route53();
    const params = {
      HostedZoneId: process.env.ROUTE53_HOSTED_ZONE_ID,
      ChangeBatch: {
        Changes: [{ Action: "UPSERT", ResourceRecordSet: dnsData }],
      },
    };
    await route53.changeResourceRecordSets(params).promise();
    console.log(`Route53 DNS record created`);
  } else {
    console.log(
      "No AWS credentials — please add the above TXT record manually."
    );
  }
  return dnsValue;
};

// Request SSL certificate from Let's Encrypt
const requestCertificate = async (subdomain) => {
  try {
    const client = await createAcmeClient();

    // create account with Let's Encrypt
    await client.createAccount({
      contact: [`mailto:${process.env.LETS_ENCRYPT_EMAIL}`],
      termsOfServiceAgreed: true,
    });

    // Create the order for the domain certificate
    const DomainName = `${subdomain}.${process.env.DOMAIN}`;
    const order = await client.createOrder({
      identifiers: [{ type: "dns", value: DomainName }],
    });

    // Get authorizations
    const authorization = await client.getAuthorizations(order);
    const identifier = authorization[0].identifier.value;
    console.log("Authorization", authorization);

    // Perform DNS-01 challenge
    // Get DNS-01 challenge
    const challenge = authorization[0].challenges.find(
      (chal) => chal.type === "dns-01"
    );
    console.log("Challenge found:", challenge);

    if (!challenge) {
      throw new Error("No DNS challenge found");
    }

    // Create DNS RECORD
    const dnsValue = await createDNSRecord(client, challenge, identifier);

    // if manual mode , wait for DNS propagation
    const isAuto =
      process.env.DNS_PROVIDER === "Route53" &&
      process.env.AWS_ACCESS_KEY_ID &&
      process.env.AWS_SECRET_ACCESS_KEY &&
      process.env.ROUTE53_HOSTED_ZONE_ID;

    if (!isAuto) {
      console.log("\n⏳ Waiting for DNS record to propagate...");
      await waitForDNSRecord(`_acme-challenge.${identifier}`, dnsValue);
    }
    // Tell ACME to verify the challenge
    await client.verifyChallenge(authorization, challenge);

    // wait for validation
    await client.waitForValidStatus(challenge);
    console.log("=====DNS challenge validated successfully!====");

    // Finalize certificate
    const [csr, privateKey] = await acmeClient.forge.createCsr({
      commonName: DomainName,
    });
    const cert = await client.finalizeOrder(order, csr);

    console.log("Certificate issued successfully!");
    saveCertificateFiles(DomainName, cert, privateKey);
    return { cert, privateKey };

    // Poll for DNS validation success
    // let result;
    // let attempts = 0;
    // while (attempts < 30) {
    //   // Poll for a max of 30 attempts
    //   attempts++;
    //   console.log(`Polling attempt ${attempts}...`);
    //   // Get the authorization status
    //   result = await client.getAuthorizations(challenge.url);
    //   if (result.status === "valid") {
    //     console.log("DNS validation successful");
    //     break;
    //   }

    //   console.log("DNS validation in progress...");
    //   // Wait for 10 seconds before retrying
    //   await new Promise((resolve) => setTimeout(resolve, 10000));
    // }

    // if (result.status !== "valid") {
    //   throw new Error("DNS validation failed");
    // }

    // // Finalize the certificate order
    // const certificate = await client.finalizeOrder(order, challenge);
    // return certificate;
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
