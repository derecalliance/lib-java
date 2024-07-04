package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecSecret;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class RecoveredState {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

//    LibIdentity sharerIdentity;
    ConcurrentHashMap<String, Integer> helperPublicEncryptionKeyToPublicKeyIdMap = new ConcurrentHashMap<>();
    ConcurrentHashMap<DeRecSecret.Id, SecretImpl> secretsMap = new ConcurrentHashMap<>();

    public void addSecret(SecretImpl secret) {
        synchronized (secretsMap) {
            secretsMap.put(secret.getSecretId(), secret);
        }
    }
//    public void setSharerIdentity(LibIdentity sharerIdentity) {
//        this.sharerIdentity = sharerIdentity;
//    }

    public void registerHelperPublicEncryptionKeyAndPublicKeyId(String helperPublicEncryptionKey,
                                                                Integer helperPublicKeyId) {
        helperPublicEncryptionKeyToPublicKeyIdMap.put(helperPublicEncryptionKey, helperPublicKeyId);
    }
//    public boolean helperPublicEncryptionKeyExists(String helperPublicEncryptionKey) {
//        return helperPublicEncryptionKeyToPublicKeyIdMap.containsKey(helperPublicEncryptionKey);
//    }

    public ConcurrentHashMap<String, Integer> getHelperPublicEncryptionKeyToPublicKeyIdMap() {
        return helperPublicEncryptionKeyToPublicKeyIdMap;
    }

//    public LibIdentity getSharerIdentity() {
//        return sharerIdentity;
//    }

    public ConcurrentHashMap<DeRecSecret.Id, SecretImpl> getSecretsMap() {
        return secretsMap;
    }

    public SecretImpl getSecret(DeRecSecret.Id secretId) {
        return secretsMap.get(secretId);
    }
}
