/**
 * Sentara Payment Gateway — Transaction Signing & Encryption Module
 * Handles CHD (Cardholder Data) encryption and payment transaction signing.
 * CRITICAL: Uses RSA-2048 and ECDSA-P256 — both quantum-vulnerable.
 */

const crypto = require('crypto');
const https = require('https');

// ─────────────────────────────────────────────────────────────────────────────
// CRITICAL: Hardcoded RSA private key in source code — PCI-DSS violation
// HNDL Risk: Any adversary capturing today's traffic can decrypt payment data
// ─────────────────────────────────────────────────────────────────────────────
const PAYMENT_SIGNING_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA_DEMO_ONLY_NOT_REAL_KEY_ROTATE_IMMEDIATELY
-----END RSA PRIVATE KEY-----`;

// CRITICAL: JWT secret hardcoded — must be rotated immediately
const jwt_secret = "s3nt4r4_p4ym3nt_s3cr3t_2024";

// VULNERABLE: ECDH P-256 key exchange — Shor's algorithm breaks this
function generateECDHSession() {
    const ecdh = crypto.createECDH('prime256v1'); // P-256 curve — quantum-vulnerable
    const publicKey = ecdh.generateKeys();
    return { ecdh, publicKey };
}

// CRITICAL: RSA-OAEP encryption of CHD — quantum-vulnerable
function encryptCardholderData(cardData, publicKeyPem) {
    const encrypted = crypto.publicEncrypt({
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, Buffer.from(JSON.stringify(cardData)));
    return encrypted.toString('base64');
}

// CRITICAL: SHA-1 for transaction fingerprinting — deprecated
function generateTransactionFingerprint(txData) {
    return crypto.createHash('sha1').update(JSON.stringify(txData)).digest('hex');
}

// VULNERABLE: TLS configuration with legacy protocols allowed
const tlsConfig = {
    minVersion: 'TLSv1',  // CRITICAL: TLS 1.0 is broken and deprecated
    ciphers: 'RC4-SHA:3DES-EDE-CBC-SHA:AES256-SHA',  // CRITICAL: RC4 and 3DES are broken
    rejectUnauthorized: false,  // CRITICAL: Disabled cert validation — MITM attack possible
};

// MEDIUM: AES-128 — should be AES-256 for CHD
function encryptAtRest(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv); // Should be aes-256-gcm
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), data: encrypted };
}

// QUANTUM_SAFE: HMAC-SHA256 (acceptable for integrity)
function computeTransactionMAC(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

module.exports = {
    generateECDHSession,
    encryptCardholderData,
    generateTransactionFingerprint,
    encryptAtRest,
    computeTransactionMAC
};
