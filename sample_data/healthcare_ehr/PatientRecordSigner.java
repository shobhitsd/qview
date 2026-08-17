package com.sentara.healthcare.ehr;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

/**
 * Sentara Healthcare Electronic Health Record (EHR) & Genomic Data Signer
 * Demonstrates legacy cryptographic primitives protecting long-lived patient PHI.
 */
public class PatientRecordSigner {

    // Vulnerable: RSA-2048 Digital Signature for clinical records
    public byte[] signPatientGenomicRecord(byte[] patientData, KeyPair keyPair) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "SunRsaSign");
        signature.initSign(keyPair.getPrivate());
        signature.update(patientData);
        return signature.sign();
    }

    // Vulnerable: ECDSA with NIST P-256 for provider identity
    public byte[] signProviderPrescription(byte[] prescriptionData, KeyPair ecPair) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecPair.getPrivate());
        ecdsa.update(prescriptionData);
        return ecdsa.sign();
    }

    // Vulnerable: Diffie-Hellman Key Agreement for FHIR Interoperability API
    public byte[] establishFHIRSessionKey(KeyPair dhPair) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(dhPair.getPrivate());
        return keyAgree.generateSecret();
    }

    // Vulnerable: TripleDES legacy cipher in patient portal
    public byte[] encryptLegacyPatientId(byte[] rawId, byte[] keyBytes) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(rawId);
    }

    // Vulnerable: MD5 checksum on pediatric imaging records
    public byte[] computeImageChecksum(byte[] dicomImage) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(dicomImage);
    }
}
