/**
 * PQC-Ready Modern Microservice — Document Signing Service
 * Demonstrates proper quantum-safe cryptography patterns.
 * Uses ML-DSA-65 (FIPS 204) via BouncyCastle PQC provider.
 */

package com.sentara.modern;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.*;

public class QuantumSafeDocumentSigner {

    static {
        // Register BCPQC provider for ML-DSA / ML-KEM support
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /**
     * QUANTUM_SAFE: ML-DSA-65 (FIPS 204) digital signature
     * Provides: 128-bit quantum security
     * Replaces: ECDSA-P256 (0-bit quantum security)
     */
    public KeyPair generateMLDSAKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BCPQC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_65);
        return kpg.generateKeyPair();
    }

    /**
     * QUANTUM_SAFE: ML-DSA-65 document signature (FIPS 204)
     */
    public byte[] signDocument(PrivateKey privateKey, byte[] documentHash)
            throws GeneralSecurityException {
        Signature signer = Signature.getInstance("ML-DSA-65", "BCPQC");
        signer.initSign(privateKey);
        signer.update(documentHash);
        return signer.sign();
    }

    /**
     * QUANTUM_SAFE: AES-256-GCM for document encryption at rest
     * Note: AES-256 has 128-bit quantum security (Grover halves key size)
     */
    public byte[] encryptDocumentAES256GCM(byte[] document, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(document);
    }

    /**
     * QUANTUM_SAFE: ML-KEM-768 (FIPS 203) for symmetric key encapsulation
     */
    public KeyPair generateMLKEMKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        kpg.initialize(768); // ML-KEM-768 = 128-bit quantum security
        return kpg.generateKeyPair();
    }

    /**
     * QUANTUM_SAFE: SHA-3-256 for document hashing
     */
    public byte[] hashDocument(byte[] document) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        return md.digest(document);
    }
}
