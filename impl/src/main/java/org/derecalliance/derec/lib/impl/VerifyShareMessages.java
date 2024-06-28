package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.ResultOuterClass;
import org.derecalliance.derec.protobuf.Verify;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;

import static org.derecalliance.derec.lib.impl.MessageFactory.createVerifyShareRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class VerifyShareMessages {

    /**
     * Sends the VerifyShareRequestMessage.
     *
     * @param senderId      DeRecIdentity of the message sender
     * @param receiverId    DeRecIdentity of the message receiver
     * @param secretId      Secret Id of the secret this message is being sent in the context of
     * @param publicKeyId   The public key id of the message sender
     * @param versionNumber Version number of the share being verified
     * @param nonce         Challenge nonce
     */
    public static void sendVerifyShareRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            int versionNumber, byte[] nonce) {
        Derecmessage.DeRecMessage deRecMessage = createVerifyShareRequestMessage(senderId, receiverId, secretId,
                versionNumber, nonce);
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    /**
     * Sends  the VerifyShareResponseMessage
     *
     * @param senderId      DeRecIdentity of the message sender
     * @param receiverId    DeRecIdentity of the message receiver
     * @param secretId      Secret Id of the secret this message is being sent in the context of
     * @param publicKeyId   The public key id of the message sender
     * @param result        Handling status of the message
     * @param versionNumber Version number of the share being verified
     * @param nonce         Challenge nonce
     * @param hash          Challenge nonce + CommittedDeRecShare hash
     */
    public static void sendVerifyShareResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result, int versionNumber, byte[] nonce, byte[] hash) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());
        staticLogger.debug("In sendVerifyShareResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createVerifyShareResponseMessage(
                senderId, receiverId, secretId,
                result, versionNumber, nonce, hash);
        staticLogger.debug("Generated sendVerifyShareResponseMessage: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending sendVerifyShareResponseMessage ");
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), false, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    /**
     * Calculates hash based on the challenge nonce sent in the VerifyShareRequest and the share
     *
     * @param data  CommittedDeRecShare bytes
     * @param nonce Challenge nonce
     * @return Hash of the concatenation of the data and nonce
     */
    static byte[] calculateVerificationHash(byte[] data, byte[] nonce) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());

        try {
            byte[] combined = new byte[data.length + nonce.length];
            System.arraycopy(data, 0, combined, 0, data.length);
            System.arraycopy(nonce, 0, combined, data.length, nonce.length);
            // Compute SHA-384 hash
            MessageDigest digest = MessageDigest.getInstance("SHA-384");
            return digest.digest(combined);
        } catch (Exception ex) {
            staticLogger.error("Exception in calculateVerificationHash");
            ex.printStackTrace();
            throw new RuntimeException("Exception in calculateVerificationHash");

        }
    }

    /**
     * Handles receiving a VerifyShareRequest. Checks whether the Helper has the share specified and updates the Result
     * of the message.
     *
     * @param publicKeyId The public key id of the message sender
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    Secret Id of the secret this message was sent in the context of
     * @param message     The VerifyShareRequestMessage received
     */
    public static void handleVerifyShareRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                Verify.VerifyShareRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());

        try {
            staticLogger.debug("In handleVerifyShareRequest");
            if (!(LibState.getInstance().getMeHelper().sharerStatuses.containsKey(senderId) &&
                    LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).containsKey(secretId))) {
                staticLogger.debug("VerifyShare request received for unknow Sharer.Secret: <" + senderId + "." + secretId + ">");
                return;
            }
            var sharerStatus = LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).get(secretId);

            int versionNumber = message.getVersion();
            byte[] nonce = message.getNonce().toByteArray();

            ShareImpl share = (ShareImpl) LibState.getInstance().getMeHelper().getShare(senderId, secretId,
                    versionNumber);

            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(share == null ? ResultOuterClass.StatusEnum.UNKNOWN_SHARE_VERSION : ResultOuterClass.StatusEnum.OK)
                    .build();
            byte[] hash = share == null ? new byte[]{} : calculateVerificationHash(share.getCommittedDeRecShare().toByteArray(), nonce);

            staticLogger.debug("About to call sendVerifyShareResponseMessage");
            VerifyShareMessages.sendVerifyShareResponseMessage(receiverId, sharerStatus.getId(),
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result,
                    versionNumber, nonce, hash);
        } catch (Exception ex) {
            staticLogger.error("Exception in handleVerifyShareRequest");
            ex.printStackTrace();
        }
    }

    /**
     * Handles receiving a VerifyShareResponse.
     *
     * @param publicKeyId The public key id of the message sender
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    Secret Id of the secret this message was sent in the context of
     * @param message     The VerifyShareResponseMessage received
     */
    public static void handleVerifyShareResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Verify.VerifyShareResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());

        try {
            staticLogger.debug("In handleVerifyShareResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            staticLogger.debug("In handleVerifyShareResponse - Secret is: " + secret);
            if (secret != null) {
                int versionNumber = message.getVersion();
                VersionImpl version = secret.getVersionByNumber(versionNumber);
                byte[] nonce = message.getNonce().toByteArray();
                byte[] hash = message.getHash().toByteArray();

                version.handleVerificationResponse(senderId, nonce, hash, versionNumber);
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleVerifyShareResponse");
            ex.printStackTrace();
        }
    }
}
