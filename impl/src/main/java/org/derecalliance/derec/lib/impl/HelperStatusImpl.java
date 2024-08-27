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

import static org.derecalliance.derec.lib.impl.PairMessages.buildCommunicationInfo;

import java.time.Instant;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecPairingStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Communicationinfo;
import org.derecalliance.derec.protobuf.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HelperStatusImpl implements DeRecHelperStatus {
    DeRecIdentity id;
    SecretImpl secret;
    DeRecPairingStatus.PairingStatus pairingStatus;
    Instant lastVerificationTime;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public HelperStatusImpl(SecretImpl secret, DeRecIdentity id, long nonce) {
        this.id = id;
        this.secret = secret;
        pairingStatus = PairingStatus.NONE;
    }

    @Override
    public DeRecIdentity getId() {
        return id;
    }

    @Override
    public Instant getLastVerificationTime() {
        return lastVerificationTime;
    }

    public void setLastVerificationTime(Instant currentTime) {
        lastVerificationTime = currentTime;
    }

    @Override
    public DeRecPairingStatus.PairingStatus getStatus() {
        return pairingStatus;
    }

    public void setStatus(DeRecPairingStatus.PairingStatus pairingStatus) {
        this.pairingStatus = pairingStatus;
    }

    /**
     * Initiates pairing with a Helper by sending a PairRequestMessage
     *
     * @param secretId   SecretId pairing is happening for
     * @param receiverId DeRecIdentity of the message receiver
     * @param nonce      Nonce to identify pairing session
     */
    void startPairing(DeRecSecret.Id secretId, DeRecIdentity receiverId, long nonce) {

        SecretImpl secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
        if (secretId == null || secret == null) {
            return;
        }
        logger.debug("My name: " + secret.getLibId().getMyId().getName());
        Communicationinfo.CommunicationInfo communicationInfo = buildCommunicationInfo(secret.getLibId());

        PairMessages.sendPairRequestMessage(
                secret.getLibId().getMyId(),
                receiverId,
                secretId,
                id.getAddress(),
                secret.isRecovering() ? Pair.SenderKind.SHARER_RECOVERY : Pair.SenderKind.SHARER_NON_RECOVERY,
                secret.getLibId().getSignaturePublicKey(),
                secret.getLibId().getEncryptionPublicKey(),
                secret.getLibId().getPublicEncryptionKeyId(),
                communicationInfo,
                nonce,
                LibState.getInstance().getMeSharer().getParameterRange());
        // Update the pairing status of the helper
        pairingStatus = PairingStatus.INVITED;
    }

    public SecretImpl getSecret() {
        return secret;
    }

    public void setSecret(SecretImpl secret) {
        this.secret = secret;
    }

    public String toString() {
        String str = "Helper Status for Derec id: " + id.toString() + "\n";
        str += "Secret: id: " + secret.getSecretId().toString() + ", Description: " + secret.getDescription() + "\n";
        str += "Pairing status: " + pairingStatus.toString() + "\n";
        return str;
    }
}
