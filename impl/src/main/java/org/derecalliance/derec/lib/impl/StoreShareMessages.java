package org.derecalliance.derec.lib.impl;

import com.google.protobuf.InvalidProtocolBufferException;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Optional;

import static org.derecalliance.derec.lib.impl.MessageFactory.createStoreShareRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class StoreShareMessages {

    /**
     * Sends the StoreShareRequestMessage.
     *
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    Secret Id of the secret this message is being sent in the context of
     * @param publicKeyId The public key id of the message sender
     * @param share       Share being sent
     */
    public static void sendStoreShareRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ShareImpl share) {
        Derecmessage.DeRecMessage deRecMessage = createStoreShareRequestMessage(senderId, receiverId, secretId,
                share);
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    /**
     * Sends the StoreShareResponseMessage.
     *
     * @param senderId      DeRecIdentity of the message sender
     * @param receiverId    DeRecIdentity of the message receiver
     * @param secretId      Secret Id of the secret this message is being sent in the context of
     * @param publicKeyId   The public key id of the message sender
     * @param result        Handling status of the message
     * @param versionNumber Version number of the share stored
     */
    public static void sendStoreShareResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result, int versionNumber) {
        Logger staticLogger = LoggerFactory.getLogger(StoreShareMessages.class.getName());
        staticLogger.debug("In sendStoreShareResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createStoreShareResponseMessage(
                senderId, receiverId, secretId,
                result, versionNumber);
        staticLogger.debug("Generated response: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), false, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    /**
     * Handles receiving a StoreShareRequestMessage.
     *
     * @param publicKeyId The public key id of the message sender
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    Secret Id of the secret this message was sent in the context of
     * @param message     The StoreShareRequestMessage
     */
    public static void handleStoreShareRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                               Storeshare.StoreShareRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(StoreShareMessages.class.getName());

        try {
            // Process StoreShareRequestMessage
            staticLogger.debug("In handleStoreShareRequest");

            // Handle the case where we don't know the Sharer, or we don't know the secret id of the share.
            if (!(LibState.getInstance().getMeHelper().sharerStatuses.containsKey(senderId) &&
                    LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).containsKey(secretId))) {
                staticLogger.debug("StoreShare request received for unknow Sharer.Secret: <" + senderId + "." + secretId + ">");
                return;
            }
            LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.UPDATE_INDICATION, senderId, secretId, message.getVersion());
            var sharerStatus = LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).get(secretId);

            Storeshare.CommittedDeRecShare cds = null;
            try {
                cds = Storeshare.CommittedDeRecShare.parseFrom(message.getShare().toByteArray());
                staticLogger.debug("In handleStoreShareRequest: parsed Committed DeRecShare successfully");
            } catch (InvalidProtocolBufferException ex) {
                staticLogger.error("Exception in trying to parse the committed derec share");
                ex.printStackTrace();
                return;
            }

            // Create a ShareImpl to store this received committedDeRecShare locally
            ShareImpl share = new ShareImpl(secretId, message.getVersion(), sharerStatus, cds);
            LibState.getInstance().getMeHelper().addShare(sharerStatus, secretId, message.getVersion(), share);

            // Check the keepList specified in the message, and remove any shares that are not in the keepList
            ArrayList<Integer> keepList = new ArrayList<>(message.getKeepListList());
            LibState.getInstance().getMeHelper().deleteCommittedDerecSharesBasedOnUpdatedKeepList(senderId,
                    secretId, keepList);

            // Respond back to the sharer
            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(cds == null ? ResultOuterClass.StatusEnum.FAIL : ResultOuterClass.StatusEnum.OK)
                    .setMemo("Thank you for storing the share with me!")
                    .build();

            // Send StoreShareResponse
            StoreShareMessages.sendStoreShareResponseMessage(receiverId, sharerStatus.getId(),
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result,
                    message.getVersion());

            if (share == null) {
                staticLogger.debug("Sent sendStoreShareResponseMessage for unknown share");
            } else {
                staticLogger.debug("Sent sendStoreShareResponseMessage for secret " + share.getSecretId() + ", version " + share.getVersionNumber());
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleStoreShareRequest");
            ex.printStackTrace();
        }
    }

    /**
     * Handles receiving a StoreShareResponseMessage.
     *
     * @param publicKeyId The public key id of the message sender
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    Secret Id of the secret this message was sent in the context of
     * @param message     The StoreShareResponseMessage
     */
    public static void handleStoreShareResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                Storeshare.StoreShareResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(StoreShareMessages.class.getName());

        try {
            staticLogger.debug("In handleStoreShareResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            staticLogger.debug("In handleStoreShareResponse - Secret is: " + secret);
            // Update confirmation of share storage for the Helper
            if (secret != null) {
                VersionImpl version = secret.getVersionByNumber(message.getVersion());
                Optional<? extends DeRecHelperStatus> helperStatusOptional =
                        secret.getHelperStatuses().stream().filter(hs -> hs.getId().equals(senderId)).findFirst();
                var helperStatus = (DeRecHelperStatus) helperStatusOptional.get();
                if (helperStatus == null) {
                    staticLogger.debug("Could not find helper status for sender: " + senderId.getName());
                    return;
                }
                version.updateConfirmationShareStorage(helperStatus, true);
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleStoreShareResponse");
            ex.printStackTrace();
        }
    }
}
