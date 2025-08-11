const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const CustomerDomain = require("../models/customerDomain");
// const { requestCertificate, waitForCertificate, createDNSRecord, getCertificateStatus } = require('../utils/customer-setup');
const {
  requestCertificate,
  deployCertificateWithZeroDowntime,
  createDNSRecord,
  waitForCertificate,
  createCloudFrontDistribution,
} = require("../utils/customer-setup");
const router = express.Router();

const dotenv = require("dotenv");
dotenv.config();

// Function to create a customer domain after registration
const createCustomerDomainAfterRegistration = async (user) => {
  try {
    const subdomain = `investor.${user.domain}`; // Subdomain for the user
    const stockSymbol = user.stock_ticker_symbol.toLowerCase();
    const mappedTo = `${stockSymbol}.debsom.shop`; // Mapping destination for the subdomain

    console.log("Subdomain:", subdomain);

    // Check if the subdomain already exists in the customer domain records
    const existingDomain = await CustomerDomain.findOne({
      subdomain,
      companyName: user.companyname,
    });
    if (existingDomain) {
      console.log(
        `Subdomain ${subdomain} already exists for the company ${user.companyname}.`
      );
      return;
    }

    // Create a new customer domain record with a 'pending' status
    const customerDomain = new CustomerDomain({
      companyName: user.companyname,
      stockSymbol: user.stock_ticker_symbol,
      companyWebsite: `https://${user.domain}`,
      subdomain,
      mappedTo,
      customerDNSProvider: "Route 53", // Using AWS Route 53 for DNS management
      user: user._id,
      status: "pending",
    });

    // Request SSL certificate from Let's Encrypt (returns { certPath, keyPath })
    const { certPath, keyPath } = await requestCertificate(subdomain);

    //  save certificate paths in db
    customerDomain.sslCertPath = certPath;
    customerDomain.sslKeyPath = keyPath;
    customerDomain.status = "ssl_issued";

    await customerDomain.save();

    console.log(
      `SSL certificate issued for ${subdomain} and stored at ${certPath}`
    );

    // Deploy cert to server (optional automation step)
    // This can trigger a script to copy certs & reload Nginx
    // await deployCertificateToServer(subdomain, certPath, keyPath);
  } catch (error) {
    console.error("Error in creating customer domain:", error);
    const errorDomain = new CustomerDomain({
      companyName: user.companyname,
      stockSymbol: user.stock_ticker_symbol,
      subdomain: `investor.${user.domain}`,
      status: "error",
      errorMessage: `Error during domain creation: ${error.message}`,
    });
    await errorDomain.save();
  }
};

// Function to check and renew the certificate if it is close to expiration -------   not work with ACME , it's only for ACM format
const scheduleCertificateRenewal = async () => {
  try {
    const certificateArn = process.env.LETS_ENCRYPT_CERTIFICATE_ARN; // Get the certificate ARN (from DB or environment)
    const expiryDate = await getCertificateExpiryDate(certificateArn); // You will need to implement this method using Let's Encrypt API

    const daysToExpire = (expiryDate - Date.now()) / (1000 * 60 * 60 * 24); // Calculate days until expiration
    if (daysToExpire <= 30) {
      console.log("Certificate is expiring soon, initiating renewal...");
      const renewedCertificate = await requestCertificate(
        `investor.${process.env.DOMAIN}`
      );
      console.log("Certificate renewed successfully:", renewedCertificate);
      // Update the certificate ARN in your DB
      await updateCertificateArnInDatabase(renewedCertificate.certificateArn);
    } else {
      console.log(
        "Certificate is valid for another " + daysToExpire + " days."
      );
    }
  } catch (error) {
    console.error("Error in certificate renewal check:", error);
  }
};

//  cron should be used in production
// E.g., schedule it to run once a day
setInterval(scheduleCertificateRenewal, 24 * 60 * 60 * 1000); // Run once a day

// updated sign-up route
router.post("/sign-up", async (req, res) => {
  console.log("req.body", req.body);
  const {
    firstname,
    lastname,
    companyname,
    domain,
    email,
    phone,
    stock_ticker_symbol,
    password,
  } = req.body;

  try {
    if (!(firstname && companyname && domain && email && stock_ticker_symbol)) {
      return res.status(400).json({
        success: false,
        message: "All mandatory fields are required",
      });
    }

    // Check for spaces in domain
    if (domain.trim().includes(" ")) {
      return res.status(400).json({
        success: false,
        message:
          "White spaces are not allowed in Domain name, please check carefully!",
      });
    }

    // Validate domain format
    const domainRegex = /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return res.status(400).json({
        success: false,
        message: "Invalid domain name (e.g. company.com, mydomain.org)",
      });
    }

    // Check if email, company name, and domain already exist
    const emailExists = await User.findOne({ email });
    const companyExists = await User.findOne({ companyname });
    const domainExist = await User.findOne({ domain });

    if (emailExists) {
      return res.status(409).json({
        success: false,
        message: "This email is already registered, Please login!",
      });
    }
    if (companyExists) {
      return res.status(409).json({
        success: false,
        message:
          "This Company name is already registered, Choose a different one!",
      });
    }
    if (domainExist) {
      return res.status(409).json({
        success: false,
        message: "This Domain name is already registered!",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      firstname: firstname?.trim(),
      lastname: lastname?.trim() || "",
      companyname: companyname?.trim().toLowerCase(),
      domain: domain?.toLowerCase()?.trim(),
      stock_ticker_symbol: stock_ticker_symbol?.toUpperCase()?.trim(),
      email: email?.trim(),
      phone: phone,
      password: hashedPassword,
    });

    await newUser.save();

    // After registration, create the customer domain
    setTimeout(async () => {
      try {
        await createCustomerDomainAfterRegistration(newUser);
      } catch (err) {
        console.error("Error during customer domain creation:", err);
      }
    }, 0);

    // Generate JWT token for the user
    const payload = {
      id: newUser._id,
      email: newUser.email,
    };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    return res.status(200).json({
      success: true,
      message: "Welcome to the IR platform ",
      user: {
        firstname: newUser.firstname,
        lastname: newUser.lastname,
        companyname: newUser.companyname,
        domain: newUser.domain,
        stock_ticker_symbol: newUser.stock_ticker_symbol,
        email: newUser.email,
        phone: newUser.phone,
      },
      accessToken,
    });
  } catch (error) {
    console.error("Error during user registration:", error);
    return res.status(500).json({
      success: false,
      message: "Internal Server Error. Please try again later.",
    });
  }
});

// Route for user login -- for demo app set-up
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, "your_jwt_secret", {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
