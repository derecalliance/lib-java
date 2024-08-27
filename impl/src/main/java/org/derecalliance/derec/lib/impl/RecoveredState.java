/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
