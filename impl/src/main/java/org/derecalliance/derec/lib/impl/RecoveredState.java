package org.derecalliance.derec.lib.impl;

import java.util.concurrent.ConcurrentHashMap;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Contains the methods and data structures necessary to recover the state of the library in normal mode.
 */
public class RecoveredState {
    ConcurrentHashMap<DeRecSecret.Id, SecretImpl> secretsMap = new ConcurrentHashMap<>();
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    /**
     * Add a secret to the secretsMap
     *
     * @param secret
     */
    public void addSecret(SecretImpl secret) {
        synchronized (secretsMap) {
            secretsMap.put(secret.getSecretId(), secret);
        }
    }

    /**
     * Get the secretsMap
     *
     * @return secretsMap
     */
    public ConcurrentHashMap<DeRecSecret.Id, SecretImpl> getSecretsMap() {
        return secretsMap;
    }

    /**
     * Get a specific secret from secretsMap
     *
     * @param secretId SecretId of the secret
     * @return secret
     */
    public SecretImpl getSecret(DeRecSecret.Id secretId) {
        return secretsMap.get(secretId);
    }
}
