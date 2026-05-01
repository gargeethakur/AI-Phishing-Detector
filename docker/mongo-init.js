// MongoDB Init Script — runs once on first container start

db = db.getSiblingDB('phishing_detector');

// Collections
db.createCollection('messages');
db.createCollection('flagged');
db.createCollection('patterns');

// Indexes for fast querying
db.messages.createIndex({ created_at: -1 });
db.messages.createIndex({ risk_level: 1 });
db.flagged.createIndex({ platform: 1, created_at: -1 });

// Seed one sample flagged record
db.flagged.insertOne({
  message: "SAMPLE: Your SBI KYC is pending. Share OTP to avoid block.",
  risk_level: "CRITICAL",
  confidence: 0.92,
  categories: ["kyc_fraud", "otp_theft"],
  platform: "whatsapp",
  created_at: new Date()
});

print("phishing_detector DB initialized.");