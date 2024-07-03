package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.lib.LibState;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecPairingStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Timer;
import java.util.TimerTask;

//import static org.derecalliance.derec.api.MessageFactory.*;
//import static org.derecalliance.derec.lib.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.MessageFactory.createUnpairRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class UnpairMessages {
    public static void sendUnpairRequestMessage (
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            String memo) {
        Logger staticLogger = LoggerFactory.getLogger(UnpairMessages.class.getName());
        staticLogger.debug("In sendUnpairRequestMessage");
        Derecmessage.DeRecMessage deRecMessage = createUnpairRequestMessage(senderId, receiverId, secretId,
                memo);

        byte[] msgBytes = getPackagedBytes(receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), true, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void sendUnpairResponseMessage (
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result) {
        Logger staticLogger = LoggerFactory.getLogger(UnpairMessages.class.getName());

        staticLogger.debug("In sendUnpairResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createUnpairResponseMessage(
                senderId, receiverId, secretId,
                result);
        staticLogger.debug("Generated response: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
        byte[] msgBytes = getPackagedBytes(receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), false, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void handleUnpairRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                               Unpair.UnpairRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(UnpairMessages.class.getName());

        try {
            // Process UnpairRequestMessage
            staticLogger.debug("In handleUnpairRequest");

            LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.UNPAIR_INDICATION, senderId, secretId, -1);

            boolean requestOk = false;
            if (!(LibState.getInstance().getMeHelper().sharerStatuses.containsKey(senderId) &&
                    LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).containsKey(secretId))) {
                staticLogger.debug("Unpair request received for unknown Sharer.Secret: <" + senderId + "." + secretId +
                        ">");
            } else {
                requestOk = true;
                var sharerToUnpair =
                         LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).get(secretId);
                sharerToUnpair.setPairingStatus(DeRecPairingStatus.PairingStatus.PENDING_REMOVAL);
                Timer timer = new Timer();
                TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        staticLogger.debug("Timer expired in Unpair messages");
                        staticLogger.debug("Sharer statuses are:" + LibState.getInstance().getMeHelper().sharerStatusesToString());
                        staticLogger.debug("Calling removeSharer for: " + senderId.getName() + "key: " + senderId.getPublicEncryptionKey() +
                                "secretid: " + secretId);
                        LibState.getInstance().getMeHelper().removeSharer(senderId, secretId);
                    }
                };
                timer.schedule(task, 20000);
            }
            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(requestOk ? ResultOuterClass.StatusEnum.OK : ResultOuterClass.StatusEnum.FAIL)
                    .build();
            staticLogger.debug("About to call sendUnpairResponseMessage");
            UnpairMessages.sendUnpairResponseMessage(receiverId, senderId,
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result);

        } catch (Exception ex) {
            staticLogger.error("Exception in handleUnpairRequest", ex);
        }
    }

    public static void handleUnpairResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Unpair.UnpairResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(UnpairMessages.class.getName());

        try {
            staticLogger.debug("In handleUnpairResponse from " + senderId.getName());
            // nothing to do
        } catch (Exception ex) {
            staticLogger.error("Exception in handleVerifyShareResponse", ex);
        }
    }
}
