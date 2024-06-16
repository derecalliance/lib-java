package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.lib.LibState;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecPairingStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;

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
        System.out.println("In sendUnpairRequestMessage");
        Derecmessage.DeRecMessage deRecMessage = createUnpairRequestMessage(senderId, receiverId, secretId,
                memo);

        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void sendUnpairResponseMessage (
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result) {
        System.out.println("In sendUnpairResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createUnpairResponseMessage(
                senderId, receiverId, secretId,
                result);
        System.out.println("Generated response: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), false, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void handleUnpairRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                               Unpair.UnpairRequestMessage message) {
        try {
            // Process UnpairRequestMessage
            System.out.println("In handleUnpairRequest");

            LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.UNPAIR_INDICATION, senderId, secretId, -1);

            boolean requestOk = false;
            if (!(LibState.getInstance().getMeHelper().sharerStatuses.containsKey(senderId) &&
                    LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).containsKey(secretId))) {
                System.out.println("Unpair request received for unknown Sharer.Secret: <" + senderId + "." + secretId +
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
                        System.out.println("Timer expired in Unpair messages");
                        System.out.println("Sharer statuses are:" + LibState.getInstance().getMeHelper().sharerStatusesToString());
                        System.out.println("Calling removeSharer for: " + senderId.getName() + "key: " + senderId.getPublicEncryptionKey() +
                                "secretid: " + secretId);
                        LibState.getInstance().getMeHelper().removeSharer(senderId, secretId);
                    }
                };
                timer.schedule(task, 20000);
            }
            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(requestOk ? ResultOuterClass.StatusEnum.OK : ResultOuterClass.StatusEnum.FAIL)
                    .build();
            System.out.println("About to call sendUnpairResponseMessage");
            UnpairMessages.sendUnpairResponseMessage(receiverId, senderId,
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result);

        } catch (Exception ex) {
            System.out.println("Exception in handleUnpairRequest");
            ex.printStackTrace();
        }
    }

    public static void handleUnpairResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Unpair.UnpairResponseMessage message) {
        try {
            System.out.println("In handleUnpairResponse from " + senderId.getName());
            // nothing to do
        } catch (Exception ex) {
            System.out.println("Exception in handleVerifyShareResponse");
            ex.printStackTrace();
        }
    }
}
