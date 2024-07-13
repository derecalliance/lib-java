package org.derecalliance.derec.lib.impl;

import java.security.MessageDigest;
import java.util.Base64;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LibIdentity {
    private DeRecIdentity myId;
    private String encryptionPrivateKey;
    private String encryptionPublicKey;
    private String signaturePrivateKey;
    private String signaturePublicKey;
    private int publicEncryptionKeyId;
    private int publicSignatureKeyId;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    /**
     * LibIdentity constructor that generates encryption and signature key pairs and sets class variables
     *
     * @param name    User's name
     * @param contact User's contact
     * @param address User's address
     */
    public LibIdentity(String name, String contact, String address) {
        try {
            Object[] encryptionKeyPair;
            Object[] signatureKeyPair;

            // Generate encryption key pair using crypto library
            encryptionKeyPair = LibState.getInstance().getDerecCryptoImpl().encryptionKeyGen();
            String encryptionPrivateKey = Base64.getEncoder().encodeToString(((byte[]) encryptionKeyPair[1]));
            String encryptionPublicKey = Base64.getEncoder().encodeToString(((byte[]) encryptionKeyPair[0]));
            int publicEncryptionKeyId = getLast32BitsOfMD5(encryptionPublicKey);

            // Generate signature key pair using crypto library
            signatureKeyPair = LibState.getInstance().getDerecCryptoImpl().signatureKeyGen();
            String signaturePrivateKey = Base64.getEncoder().encodeToString(((byte[]) signatureKeyPair[1]));
            String signaturePublicKey = Base64.getEncoder().encodeToString(((byte[]) signatureKeyPair[0]));
            int publicSignatureKeyId = getLast32BitsOfMD5(signaturePublicKey);

            setVariables(
                    name,
                    contact,
                    address,
                    encryptionPrivateKey,
                    encryptionPublicKey,
                    signaturePrivateKey,
                    signaturePublicKey,
                    publicEncryptionKeyId,
                    publicSignatureKeyId);
        } catch (Exception ex) {
            logger.error("Exception in LibIdentity", ex);
        }
    }

    /**
     * LibIdentity constructor that sets class variables
     */
    public LibIdentity(
            String name,
            String contact,
            String address,
            String encryptionPrivateKey,
            String encryptionPublicKey,
            String signaturePrivateKey,
            String signaturePublicKey,
            int publicEncryptionKeyId,
            int publicSignatureKeyId) {
        setVariables(
                name,
                contact,
                address,
                encryptionPrivateKey,
                encryptionPublicKey,
                signaturePrivateKey,
                signaturePublicKey,
                publicEncryptionKeyId,
                publicSignatureKeyId);
    }

    /**
     * Sets class variables and creates DeRecIdentity for the user
     */
    public void setVariables(
            String name,
            String contact,
            String address,
            String encryptionPrivateKey,
            String encryptionPublicKey,
            String signaturePrivateKey,
            String signaturePublicKey,
            int publicEncryptionKeyId,
            int publicSignatureKeyId) {
        try {
            myId = new DeRecIdentity(
                    name, contact, address, publicEncryptionKeyId, encryptionPublicKey, signaturePublicKey);
            setKeys(
                    encryptionPrivateKey,
                    encryptionPublicKey,
                    signaturePrivateKey,
                    signaturePublicKey,
                    publicEncryptionKeyId,
                    publicSignatureKeyId);
        } catch (Exception ex) {
            logger.error("Exception in LibIdentity.setVariables", ex);
        }
    }

    /**
     * Sets keys
     */
    public void setKeys(
            String encryptionPrivateKey,
            String encryptionPublicKey,
            String signaturePrivateKey,
            String signaturePublicKey,
            int publicEncryptionKeyId,
            int publicSignatureKeyId) {
        try {
            this.encryptionPrivateKey = encryptionPrivateKey;
            this.encryptionPublicKey = encryptionPublicKey;
            this.signaturePrivateKey = signaturePrivateKey;
            this.signaturePublicKey = signaturePublicKey;
            this.publicEncryptionKeyId = publicEncryptionKeyId;
            this.publicSignatureKeyId = publicSignatureKeyId;
        } catch (Exception ex) {
            logger.error("Exception in LibIdentity.setKeys", ex);
        }
    }

    public DeRecIdentity getMyId() {
        return myId;
    }

    public String getEncryptionPrivateKey() {
        return encryptionPrivateKey;
    }

    public String getEncryptionPublicKey() {
        return encryptionPublicKey;
    }

    public String getSignaturePrivateKey() {
        return signaturePrivateKey;
    }

    public String getSignaturePublicKey() {
        return signaturePublicKey;
    }

    public int getPublicEncryptionKeyId() {
        return publicEncryptionKeyId;
    }

    public int getPublicSignatureKeyId() {
        return publicSignatureKeyId;
    }

    /**
     * Used to generate the publicEncryptionKeyId and publicSignatureKeyId
     *
     * @param input String input
     * @return last 32 bits of the MD5 hash
     */
    public static int getLast32BitsOfMD5(String input) {
        Logger staticLogger = LoggerFactory.getLogger(LibIdentity.class.getName());
        try {
            // Create MD5 Hash
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();

            // Extract the last 4 bytes (32 bits) of the MD5 hash
            byte[] last4Bytes = new byte[4];
            System.arraycopy(digest, digest.length - 4, last4Bytes, 0, 4);

            // Convert the last 4 bytes to an int32
            int result = (last4Bytes[0] << 24) & 0xFF000000
                    | (last4Bytes[1] << 16) & 0x00FF0000
                    | (last4Bytes[2] << 8) & 0x0000FF00
                    | (last4Bytes[3]) & 0x000000FF;
            staticLogger.debug("For input " + input + " getLast32BitsOfMD5() generated result " + result);
            return result;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
