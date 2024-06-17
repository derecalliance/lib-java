package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Share;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.ResultOuterClass;
import org.derecalliance.derec.protobuf.Secretidsversions;

import java.nio.charset.StandardCharsets;
import java.util.*;

//import static org.derecalliance.derec.api.MessageFactory.createGetSecretIdsVersionsRequestMessage;
//import static org.derecalliance.derec.api.MessageFactory.getPackagedBytes;
//import static org.derecalliance.derec.lib.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.MessageFactory.createGetSecretIdsVersionsRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class GetSecretIdsVersionsMessages {
    public static void sendGetSecretIdsVersionsRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId) {
        var hs = (HelperStatusImpl)
                ((SecretImpl)LibState.getInstance().getMeSharer().getSecret(secretId)).getHelperStatusById(receiverId);
        LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.LIST_SECRET_PROGRESS,
                DeRecStatusNotification.NotificationSeverity.UNCLASSIFIED,
                "Sending GetSecretIdsVersionsRequest",
                (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId), null, hs);

        Derecmessage.DeRecMessage deRecMessage = createGetSecretIdsVersionsRequestMessage(senderId, receiverId, secretId);
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void sendGetSecretIdsVersionsResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result, HashMap<DeRecSecret.Id, ArrayList<Integer>> secretIdAndVersions) {
        System.out.println("In sendGetSecretIdsVersionsResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createGetSecretIdsVersionsResponseMessage(
                senderId, receiverId, secretId,
                result, secretIdAndVersions);
        System.out.println("Generated sendGetSecretIdsVersionsResponseMessage: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending sendGetSecretIdsVersionsResponseMessage ");
        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), false, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }
    

    public static void handleGetSecretIdsVersionsRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                Secretidsversions.GetSecretIdsVersionsRequestMessage message) {
        try {
            System.out.println("In handleGetSecretIdsVersionsRequest");
            boolean found = false;
            // First find any one previously stored share that matches the secretId in the GetSecretIdsVersionsRequest
            // message
            Optional<ShareImpl> matchedShareOptional = ((List<ShareImpl>) LibState.getInstance().getMeHelper().getShares())
                    .stream()
                    .filter(s -> Arrays.equals(s.getSecretId().getBytes(), secretId.getBytes()))
                    .findFirst();
            HashMap<DeRecSecret.Id, ArrayList<Integer>> secretIdAndVersions = new HashMap<>();
            if (!matchedShareOptional.isPresent()) {
                System.out.println("No matching share found");
                found = false;
            } else {
                // Find the sharerStatus that had stored this share previously. Basically, get the sharerStatus of
                // the helper that has been lost
                SharerStatusImpl lostSharer = (SharerStatusImpl) matchedShareOptional.get().getSharerStatus();
                // Now find all shares that this lost sharer had stored and harvest secretIds and versionNumbers from
                // these shares
                for (ShareImpl share: (List<ShareImpl>)LibState.getInstance().getMeHelper().getShares()) {
                    if (share.getSharer().getId().getPublicEncryptionKey().equals(lostSharer.getId().getPublicEncryptionKey())) {
                        DeRecSecret.Id sid = share.getSecretId();
                        if (!secretIdAndVersions.containsKey(sid)) {
                            secretIdAndVersions.put(sid, new ArrayList<>());
//                            System.out.println("Found previously stored secret " + new String(sid.getBytes(),
//                                    StandardCharsets.UTF_8));
                            System.out.println("Found previously stored secret " + Base64.getEncoder().encodeToString(sid.getBytes()));
                            found = true;
                        }
                        secretIdAndVersions.get(sid).add(share.getVersionNumber());
                    }
                }
            }

            var uiResponse =
                    (HelperImpl.NotificationResponse) LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.LIST_SECRETS_INDICATION, senderId, secretId, -1);

            boolean okToSend = false;
            if (found && uiResponse.getResult()) {
                okToSend = true;
            }
            System.out.println("About to call sendGetSecretIdsVersionsResponseMessage");
            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(okToSend ? ResultOuterClass.StatusEnum.OK : ResultOuterClass.StatusEnum.FAIL)
                    .setMemo(okToSend ? "Found Shares" : "Shares not found")
                    .build();
            GetSecretIdsVersionsMessages.sendGetSecretIdsVersionsResponseMessage(receiverId, senderId,
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result,
                    okToSend ? secretIdAndVersions : new HashMap<>());
        } catch (Exception ex) {
            System.out.println("Exception in handleGetSecretIdsVersionsRequest");
            ex.printStackTrace();
        }
    }


    public static void handleGetSecretIdsVersionsResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Secretidsversions.GetSecretIdsVersionsResponseMessage message) {
        try {
            System.out.println("In handleGetSecretIdsVersionsResponse from " + senderId.getName());
            // Get HelperStatus from the senderId
            Optional<HelperStatusImpl> helperStatusOptional =
                    (Optional<HelperStatusImpl>) LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream()
                    .filter(hs -> hs.getId().getPublicEncryptionKey().equals(senderId.getPublicEncryptionKey()))
                    .findFirst();
            HelperStatusImpl helperStatus = helperStatusOptional.get();

            if (message.getResult().getStatus() != ResultOuterClass.StatusEnum.OK) {
                LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.LIST_SECRET_FAILED,
                        DeRecStatusNotification.NotificationSeverity.ERROR, "getSecretIdsVersionsResponse failed",
                        null, null, helperStatus);
                return;
            } else {
                LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.LIST_SECRET_AVAILABLE,
                        DeRecStatusNotification.NotificationSeverity.NORMAL,
                        "getSecIdsVersResponse received",
                        null, null, helperStatus);
            }

            for (Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList secretListItem:
                    message.getSecretListList()) {
                System.out.println("Got secret: " +
                                Base64.getEncoder().encodeToString(secretListItem.getSecretId().toByteArray()));

                if (secretId.equals(new DeRecSecret.Id(secretListItem.getSecretId().toByteArray()))) {
                    // Register that this helper has these versions. The periodic task will send out the getShareRequests
                    LibState.getInstance().getMeSharer().getRecoveryContext().helperHasVersions(
                            new DeRecSecret.Id(secretListItem.getSecretId().toByteArray()),
                            helperStatus, new ArrayList<>(secretListItem.getVersionsList()));
                } else {
                    System.out.println("I am processing secret " + secretId + ", but I found a new secret " + new DeRecSecret.Id(secretListItem.getSecretId().toByteArray()));
                    LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.RECOVERY_SECRET_SHARE_DISCOVERED,
                            DeRecStatusNotification.NotificationSeverity.NORMAL,
                            "Recoverable Secret/Share discovered: " + new DeRecSecret.Id(secretListItem.getSecretId().toByteArray()),
                            null, null, helperStatus);
                }
            }
        } catch (Exception ex) {
            System.out.println("Exception in handleGetSecretIdsVersionsResponse");
            ex.printStackTrace();
        }
    }
}