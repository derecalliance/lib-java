package org.derecalliance.derec.lib.impl;

import com.google.protobuf.InvalidProtocolBufferException;
//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Share;
//import org.derecalliance.derec.lib.Version;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;

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
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void sendStoreShareResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result, int versionNumber) {
        System.out.println("In sendStoreShareResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createStoreShareResponseMessage(
                senderId, receiverId, secretId,
                result, versionNumber);
        System.out.println("Generated response: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }


    public static void handleStoreShareRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                   Storeshare.StoreShareRequestMessage message) {
        try {
            // Process StoreShareRequestMessage
            System.out.println("In handleStoreShareRequest");

            if (!(LibState.getInstance().getMeHelper().sharerStatuses.containsKey(senderId) &&
                    LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).containsKey(secretId))) {
                System.out.println("StoreShare request received for unknow Sharer.Secret: <" + senderId + "." + secretId + ">");

                return;
            }
            LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.UPDATE_INDICATION, senderId, secretId, message.getVersion());
            var sharerStatus = LibState.getInstance().getMeHelper().sharerStatuses.get(senderId).get(secretId);

            try {
                CommittedDeRecShare cds =
                        new CommittedDeRecShare(Storeshare.CommittedDeRecShare.parseFrom(message.getShare().toByteArray()));
                System.out.println("In handleStoreShareRequest Committed DeRecShare  is: " + cds.toString());
            } catch (InvalidProtocolBufferException ex) {
                System.out.println("Exception in trying to parse the committed derec share");
                ex.printStackTrace();
            }

            ShareImpl share = new ShareImpl(secretId, message.getVersion(), sharerStatus, message.getShare().toByteArray());
            LibState.getInstance().getMeHelper().addShare(sharerStatus, secretId, message.getVersion(), share);
            System.out.println("Added ShareImpl");

            ArrayList<Integer> keepList =  new ArrayList<>(message.getKeepListList());
            LibState.getInstance().getMeHelper().deleteCommittedDerecSharesBasedOnUpdatedKeepList(senderId,
                    secretId, keepList);

            // Respond back to the sharer
            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(ResultOuterClass.StatusEnum.OK)
                    .setMemo("Thank you for storing the share with me!")
                    .build();
            System.out.println("About to call sendStoreShareResponseMessage");
            // Send StoreShareResponse
            StoreShareMessages.sendStoreShareResponseMessage(receiverId, sharerStatus.getId(),
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result,
                    share.getVersionNumber());


        } catch (Exception ex) {
            System.out.println("Exception in handleStoreShareRequest");
            ex.printStackTrace();
        }
    }


    public static void handleStoreShareResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Storeshare.StoreShareResponseMessage message) {
        try {
            System.out.println("In handleStoreShareResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            System.out.println("In handleStoreShareResponse - Secret is: " + secret);
            if (secret != null) {
                VersionImpl version = secret.getVersionByNumber(message.getVersion());
                Optional<? extends DeRecHelperStatus> helperStatusOptional =
                        secret.getHelperStatuses().stream().filter(hs -> hs.getId().equals(senderId)).findFirst();
                var helperStatus = (DeRecHelperStatus)helperStatusOptional.get();
                if (helperStatus == null) {
                    System.out.println("Could not find helper status for sender: " + senderId.getName());
                    return;
                }
                version.updateConfirmationShareStorage(helperStatus, true);
            }
        } catch (Exception ex) {
            System.out.println("Exception in handleStoreShareResponse");
            ex.printStackTrace();
        }
    }
}
