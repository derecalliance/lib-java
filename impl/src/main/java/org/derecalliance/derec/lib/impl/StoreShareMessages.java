package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Share;
//import org.derecalliance.derec.lib.Version;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

//import static org.derecalliance.derec.api.MessageFactory.*;
//import static org.derecalliance.derec.lib.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.MessageFactory.createStoreShareRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class StoreShareMessages {
    public static void sendStoreShareRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ShareImpl share) {
        Derecmessage.DeRecMessage deRecMessage = createStoreShareRequestMessage(senderId, receiverId, secretId,
                share);
        byte[] msgBytes = getPackagedBytes(receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), true, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

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
        byte[] msgBytes = getPackagedBytes(receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), false, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }


    public static void handleStoreShareRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                   Storeshare.StoreShareRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(StoreShareMessages.class.getName());

        try {
            // Process StoreShareRequestMessage
            staticLogger.debug("In handleStoreShareRequest");

            if (!(LibState.getInstance().getMeHelper().sharerStatuses.containsKey(senderId) &&
                    LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).containsKey(secretId))) {
                staticLogger.debug("StoreShare request received for unknow Sharer.Secret: <" + senderId + "." + secretId + ">");

                return;
            }
            staticLogger.debug("Share: isEmpty = " + message.getShare().isEmpty());
            staticLogger.debug("Message version: " + message.getVersion());
            Storeshare.CommittedDeRecShare cds = null;
            var sharerStatus = LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).get(secretId);

            if (!(message.getShare().isEmpty() || message.getVersion() == 0)) {
                LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.UPDATE_INDICATION, senderId, secretId, message.getVersion());

                try {
                    cds = Storeshare.CommittedDeRecShare.parseFrom(message.getShare().toByteArray());
                    staticLogger.debug("In handleStoreShareRequest: parsed Committed DeRecShare successfully");
                } catch (InvalidProtocolBufferException ex) {
                    staticLogger.error("Exception in trying to parse the committed derec share", ex);
                    return;
                }


                // Create a ShareImpl to store this received committedDeRecShare locally
                ShareImpl share = new ShareImpl(secretId, message.getVersion(), sharerStatus, cds);
                LibState.getInstance().getMeHelper().addShare(sharerStatus, secretId, message.getVersion(), share);
                staticLogger.debug("Will send sendStoreShareResponseMessage for secret " + share.getSecretId() + ", version " + share.getVersionNumber());
            }
            ArrayList<Integer> keepList =  new ArrayList<>(message.getKeepListList());
            staticLogger.debug("Received keeplist = " + keepList);
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

        } catch (Exception ex) {
            staticLogger.error("Exception in handleStoreShareRequest", ex);
        }
    }


    public static void handleStoreShareResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Storeshare.StoreShareResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(StoreShareMessages.class.getName());

        try {
            staticLogger.debug("In handleStoreShareResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            staticLogger.debug("In handleStoreShareResponse - Secret is: " + secret);
            if (secret != null) {
                VersionImpl version = secret.getVersionByNumber(message.getVersion());
                // Version is null when the Sharer sends a StoreShareRequest with no share/version (just the keepList update)
                // In this case, the versionNumber in the StoreShareResponse message is not present in the protobuf, and defaults to 0.
                // Hence the secret.getVersionByNumber(message.getVersion()) will return null
                if (version != null) {
                    Optional<? extends DeRecHelperStatus> helperStatusOptional =
                            secret.getHelperStatuses().stream().filter(hs -> hs.getId().equals(senderId)).findFirst();
                    if (helperStatusOptional.isPresent()) {
                        var helperStatus = (DeRecHelperStatus) helperStatusOptional.get();
                        version.updateConfirmationShareStorage(helperStatus, true);
                    } else {
                        staticLogger.debug("Could not find helper status for sender: " + senderId.getName());
                        return;
                    }
                }
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleStoreShareResponse", ex);
        }
    }
}
