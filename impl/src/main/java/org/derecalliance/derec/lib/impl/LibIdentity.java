package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class LibIdentity  {
    private DeRecIdentity myId;
    private String encryptionPrivateKey;
    private String encryptionPublicKey;
    private String signaturePrivateKey;
    private String signaturePublicKey;
    private int publicEncryptionKeyId;
    private int publicSignatureKeyId;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public LibIdentity(String name, String contact, String address) {
        try {
            if (LibState.getInstance().useRealCryptoLib) {
                Object[] encryptionKeyPair;
                Object[] signatureKeyPair;

                encryptionKeyPair = LibState.getInstance().getDerecCryptoImpl().encryptionKeyGen();
                String encryptionPrivateKey = Base64.getEncoder().encodeToString(((byte[]) encryptionKeyPair[1]));
                String encryptionPublicKey = Base64.getEncoder().encodeToString(((byte[]) encryptionKeyPair[0]));
                int publicEncryptionKeyId = getLast32BitsOfMD5(encryptionPublicKey);

                signatureKeyPair = LibState.getInstance().getDerecCryptoImpl().signatureKeyGen();
                String signaturePrivateKey = Base64.getEncoder().encodeToString(((byte[]) signatureKeyPair[1]));
                String signaturePublicKey = Base64.getEncoder().encodeToString(((byte[]) signatureKeyPair[0]));
                int publicSignatureKeyId = getLast32BitsOfMD5(signaturePublicKey);

                setVariables(name, contact, address, encryptionPrivateKey, encryptionPublicKey,
                        signaturePrivateKey, signaturePublicKey, publicEncryptionKeyId,
                        publicSignatureKeyId);
            } else {
                KeyPair encryptionKeyPair;
                KeyPair signatureKeyPair;

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                SecureRandom secureRandom = new SecureRandom();
                encryptionKeyPair = keyPairGenerator.generateKeyPair();
                String encryptionPrivateKey = Base64.getEncoder().encodeToString(encryptionKeyPair.getPrivate().getEncoded());
                String encryptionPublicKey = Base64.getEncoder().encodeToString(encryptionKeyPair.getPublic().getEncoded());
                int publicEncryptionKeyId = getLast32BitsOfMD5(encryptionPublicKey);

                signatureKeyPair = keyPairGenerator.generateKeyPair();
                String signaturePrivateKey = Base64.getEncoder().encodeToString(signatureKeyPair.getPrivate().getEncoded());
                String signaturePublicKey = Base64.getEncoder().encodeToString(signatureKeyPair.getPublic().getEncoded());
                int publicSignatureKeyId = getLast32BitsOfMD5(signaturePublicKey);

                setVariables(name, contact, address, encryptionPrivateKey, encryptionPublicKey,
                        signaturePrivateKey, signaturePublicKey, publicEncryptionKeyId,
                        publicSignatureKeyId);
            }
        } catch (Exception ex) {
            logger.error("Exception in LibIdentity");
            ex.printStackTrace();
        }
    }
    public LibIdentity(String name, String contact, String address,
                              String encryptionPrivateKey, String encryptionPublicKey, String signaturePrivateKey,
                              String signaturePublicKey, int publicEncryptionKeyId, int publicSignatureKeyId) {
        setVariables(name, contact, address, encryptionPrivateKey, encryptionPublicKey,
                signaturePrivateKey, signaturePublicKey, publicEncryptionKeyId,
                publicSignatureKeyId);
    }

    public void setVariables(String name, String contact, String address,
                       String encryptionPrivateKey, String encryptionPublicKey, String signaturePrivateKey,
                       String signaturePublicKey, int publicEncryptionKeyId, int publicSignatureKeyId) {
        try {
            myId = new DeRecIdentity(name, contact, address, encryptionPublicKey, signaturePublicKey);
            LibState.getInstance().messageHashToIdentityMap.put(ByteString.copyFrom(myId.getPublicEncryptionKeyDigest()),
                    myId);
            setKeys(encryptionPrivateKey, encryptionPublicKey, signaturePrivateKey,
                     signaturePublicKey, publicEncryptionKeyId, publicSignatureKeyId);
        } catch (Exception ex) {
            System.err.println("Exception in LibIdentity.setVariables");
            ex.printStackTrace();
        }
    }
    public void setKeys( String encryptionPrivateKey, String encryptionPublicKey, String signaturePrivateKey,
                          String signaturePublicKey, int publicEncryptionKeyId, int publicSignatureKeyId) {
        try {
            this.encryptionPrivateKey = encryptionPrivateKey;
            this.encryptionPublicKey = encryptionPublicKey;
            this.signaturePrivateKey = signaturePrivateKey;
            this.signaturePublicKey = signaturePublicKey;
            this.publicEncryptionKeyId = publicEncryptionKeyId;
            this.publicSignatureKeyId = publicSignatureKeyId;
        } catch (Exception ex) {
            System.err.println("Exception in LibIdentity.setKeys");
            ex.printStackTrace();
        }
    }

    public DeRecIdentity getMyId() {
        return myId;
    }

//    public KeyPair getEncryptionKeyPair() {
//        return encryptionKeyPair;
//    }

//    public KeyPair getSignatureKeyPair() {
//        return signatureKeyPair;
//    }

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

    public void setEncryptionPrivateKey(String encryptionPrivateKey) {
        this.encryptionPrivateKey = encryptionPrivateKey;
    }

    public void setEncryptionPublicKey(String encryptionPublicKey) {
        this.encryptionPublicKey = encryptionPublicKey;
    }

    public void setSignaturePrivateKey(String signaturePrivateKey) {
        this.signaturePrivateKey = signaturePrivateKey;
    }

    public void setSignaturePublicKey(String signaturePublicKey) {
        this.signaturePublicKey = signaturePublicKey;
    }

    public void setPublicEncryptionKeyId(int publicEncryptionKeyId) {
        this.publicEncryptionKeyId = publicEncryptionKeyId;
    }

    public void setPublicSignatureKeyId(int publicSignatureKeyId) {
        this.publicSignatureKeyId = publicSignatureKeyId;
    }

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
            int result =  (last4Bytes[0] << 24) & 0xFF000000 |
                    (last4Bytes[1] << 16) & 0x00FF0000 |
                    (last4Bytes[2] << 8) & 0x0000FF00 |
                    (last4Bytes[3]) & 0x000000FF;
//            int result = new BigInteger(1, last4Bytes).intValue();
            staticLogger.debug("For input " + input + " getLast32BitsOfMD5() generated result " + result);
            return result;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
