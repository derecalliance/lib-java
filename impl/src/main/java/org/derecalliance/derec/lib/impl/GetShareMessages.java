package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Share;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.protobuf.*;

import java.util.Optional;

//import static org.derecalliance.derec.api.MessageFactory.*;
//import static org.derecalliance.derec.lib.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.MessageFactory.createGetShareRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class GetShareMessages {
    public static void sendGetShareRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            int shareVersion) {
        Derecmessage.DeRecMessage deRecMessage = createGetShareRequestMessage(senderId, receiverId, secretId,
                shareVersion);
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        System.out.println("***** In sendGetShareRequestMessage sending GetShareRequest to " + receiverId.getName() +
                " for version " + shareVersion);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }


    public static void sendGetShareResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result, CommittedDeRecShare committedDeRecShare) {
        System.out.println("In sendGetShareResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createGetShareResponseMessage(
                senderId, receiverId, secretId,
                result, committedDeRecShare.createCommittedDeRecShareMessage());
        System.out.println("Generated response: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), false, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }


    public static void handleGetShareRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                               Getshare.GetShareRequestMessage message) {
        try {
            LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.RECOVER_SECRET_INDICATION, senderId, secretId, message.getShareVersion());
            // Process PairRequestMessage
            System.out.println("In handleGetShareRequest");
//            byte[] secretIdBytes = secretId.getBytes();//message.getSecretId().toByteArray();
            int versionNumber = message.getShareVersion();
            SharerStatusImpl sharerStatus = new SharerStatusImpl(senderId);
            System.out.println("In handleGetShareRequest for sharer key: " + sharerStatus.getId().getPublicEncryptionKey() + ", " +
                    "Sec id: " + secretId.toString() + " or " + message.getSecretId().toString() + ", Ver: " + versionNumber);

//            (Optional<ShareImpl>)
            System.out.println("recdCommittedShares: " + LibState.getInstance().getMeHelper().sharesToString());

            Optional <ShareImpl> shareToReturn =
                    (Optional<ShareImpl>) LibState.getInstance().getMeHelper().getShares()
                    .stream()
//    commented because the sharer's public key has changed when they are recovering...                .filter(s -> s
//    .getSharer().getId().getPublicEncryptionKey().equals(senderId
//    .getPublicEncryptionKey()))
                    .filter(s -> s.getSecretId().equals(secretId))
                    .filter(s -> s.getVersions().get(0) == versionNumber)
                    .findFirst();

            ResultOuterClass.Result result;
            CommittedDeRecShare committedDeRecShare = null;
            if (shareToReturn.isPresent()) {
                System.out.println("shareToReturn is present: from " + shareToReturn.get().getSharer().getId().getName());


                try {
                    CommittedDeRecShare cds =
                            new CommittedDeRecShare(Storeshare.CommittedDeRecShare.parseFrom(shareToReturn.get().getCommittedDeRecShareBytes()));
                    System.out.println("In handleGetShareRequest Committed DeRecShare  is: " + cds.toString());
                } catch (InvalidProtocolBufferException ex) {
                    System.out.println("Exception in trying to parse the committed derec share");
                    ex.printStackTrace();
                }



                result = ResultOuterClass.Result.newBuilder().setStatus(ResultOuterClass.StatusEnum.OK).build();
                committedDeRecShare = new CommittedDeRecShare(
                        Storeshare.CommittedDeRecShare.parseFrom(ByteString.copyFrom(shareToReturn.get().getCommittedDeRecShareBytes())));

            } else {
                System.out.println("Oops. I couldn't find a shareToReturn");
                result = ResultOuterClass.Result.newBuilder().setStatus(ResultOuterClass.StatusEnum.FAIL).build();
            }
            System.out.println("About to call sendGetShareResponseMessage, committedDeRecShare is: " + committedDeRecShare);
            // Send GetShareResponse
            GetShareMessages.sendGetShareResponseMessage(receiverId, senderId,
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(),
                    result,
                    committedDeRecShare);
        } catch (Exception ex) {
            System.out.println("Exception in handleGetShareRequest");
            ex.printStackTrace();
        }
    }


    public static void handleGetShareResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                Getshare.GetShareResponseMessage message) {
        try {
            System.out.println("In handleGetShareResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            System.out.println("In handleGetShareResponse - Secret is: " + secret);
            System.out.println("Result: " + message.getResult().getStatus().toString());
            CommittedDeRecShare committedDeRecShare = new CommittedDeRecShare(message.getCommittedDeRecShare());
            System.out.println("Version: " + committedDeRecShare.getDeRecShare().version);
            Optional<HelperStatusImpl> helperStatusOptional = (Optional<HelperStatusImpl>)
                    LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream().filter(hs -> hs.getId().getPublicEncryptionKey().equals(senderId.getPublicEncryptionKey())).findFirst();
            if (!helperStatusOptional.isPresent()) {
                System.out.println("Could not find helper status for sender: " + senderId.getName());
                return;
            }

            int versionNumber = committedDeRecShare.getDeRecShare().version;
            VersionImpl fakeVersion = new VersionImpl(secret, new byte[]{}, versionNumber);

            LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.RECOVERY_PROGRESS,
                    DeRecStatusNotification.NotificationSeverity.UNCLASSIFIED,
                    "Retrieved share",
                    secret, fakeVersion, helperStatusOptional.get());

            boolean success =
                    LibState.getInstance().getMeSharer().getRecoveryContext().saveRetrievedCommittedDeRecShare(
                    secretId, versionNumber,  helperStatusOptional.get(), committedDeRecShare);
            if (success) {
                System.out.println("Sending RECOVERY_COMPLETE notification");
                LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.RECOVERY_COMPLETE,
                        DeRecStatusNotification.NotificationSeverity.NORMAL,
                        "Recovery complete",
                        secret, secret.getVersionByNumber(versionNumber), null);
            }
        } catch (Exception ex) {
            System.out.println("Exception in handleGetShareResponse");
            ex.printStackTrace();
        }
    }
}
