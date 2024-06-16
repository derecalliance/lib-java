package org.derecalliance.derec.lib.impl;

import java.security.*;
import java.util.Base64;


public class CryptoPrimitives {

//    MessageDigest messageDigest;
//    KeyPairGenerator keyPairGenerator;
//    SecureRandom secureRandom ;
//    KeyPair testKeyPair;

//    public CryptoPrimitives() throws NoSuchAlgorithmException {
//         messageDigest = MessageDigest.getInstance("SHA-384");
//         keyPairGenerator = KeyPairGenerator.getInstance(
//                "EC");
//         secureRandom = new SecureRandom();
//    }
//    public KeyPair generateKeyPair() {
//         return (keyPairGenerator.generateKeyPair());
//    }
//    public PublicKey getPubKey(KeyPair keyPair) {
//        return (keyPair.getPublic());
//    }
//    public String getPubKeyStr(KeyPair keyPair) {
//        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
//    }
//    public String getPubKeyStr(PublicKey pubKey) {
//        return Base64.getEncoder().encodeToString(pubKey.getEncoded());
//    }

    public static byte[] dummyEncryptSecret(byte[] data) {
        // TODO implement this
        return data;
    }
    public static byte[] dummyDecryptSecret(byte[] data) {
        // TODO implement this
        return data;
    }
}
