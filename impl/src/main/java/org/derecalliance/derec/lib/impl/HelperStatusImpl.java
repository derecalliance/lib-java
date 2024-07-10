package org.derecalliance.derec.lib.impl;

// import org.derecalliance.derec.lib.LibState;
import static org.derecalliance.derec.lib.impl.PairMessages.buildCommunicationInfo;
import static org.derecalliance.derec.lib.impl.utils.MiscUtils.*;

import java.time.Instant;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecPairingStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Communicationinfo;
import org.derecalliance.derec.protobuf.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// import static org.derecalliance.derec.api.PairMessages.buildCommunicationInfo;

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
        //        startPairing(secret.getSecretId(), id, nonce);
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
