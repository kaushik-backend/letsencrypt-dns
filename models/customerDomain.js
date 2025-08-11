const mongoose = require("mongoose");

// Schema for customer domain configuration
const customerDomainSchema = new mongoose.Schema(
  {
    companyName: {
      type: String,
      required: true,
      trim: true,
    },
    stockSymbol: {
      type: String,
      required: true,
      trim: true,
      uppercase: true,
    },
    companyWebsite: {
      type: String,
      trim: true,
    },
    subdomain: {
      type: String,
      required: true,
      trim: true,
      unique: true,
    },
    mappedTo: {
      type: String,
      trim: true,
    },
    customerDNSProvider: {
      type: String,
      trim: true, // e.g., "Route53", "GoDaddy", "Manual"
    },

    // Let's Encrypt specific
    certificatePath: {
      // Where cert file is stored (PEM)
      type: String,
      trim: true,
    },
    privateKeyPath: {
      // Where key file is stored
      type: String,
      trim: true,
    },
    fullChainPath: {
      // Full chain file path
      type: String,
      trim: true,
    },
    expiryDate: {
      // When cert will expire
      type: Date,
    },

    // DNS challenge data
    dnsValidation: new mongoose.Schema(
      {
        name: { type: String, trim: true }, // _acme-challenge.subdomain
        type: { type: String, trim: true }, // Always "TXT"
        value: { type: String, trim: true }, // TXT record value
        ttl: { type: Number, default: 60 },
      },
      { _id: false }
    ),

    status: {
      type: String,
      enum: [
        "pending", // Just created
        "dns_validation", // Waiting for DNS setup
        "ssl_issued",
        "certificate_issued", // Cert generated
        "active", // Live in production
        "error", // Failed somewhere
      ],
      default: "pending",
    },

    mode: {
      // Manual or automated
      type: String,
      enum: ["manual", "automated"],
      default: "manual",
    },

    lastCheckedAt: Date,
    errorMessage: { type: String },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("CustomerDomain", customerDomainSchema);
