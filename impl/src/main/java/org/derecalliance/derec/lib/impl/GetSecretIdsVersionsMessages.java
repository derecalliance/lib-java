package org.derecalliance.derec.lib.impl;

import static org.derecalliance.derec.lib.impl.MessageFactory.createGetSecretIdsVersionsRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

import java.util.*;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.ResultOuterClass;
import org.derecalliance.derec.protobuf.Secretidsversions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GetSecretIdsVersionsMessages {

    /**
     * Sends a GetSecretIdsVersionsRequestMessage
     *
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    SecretId this message is being sent in the context of
     * @param publicKeyId publicKeyId of the receiver
     */
    public static void sendGetSecretIdsVersionsRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId) {
        var hs = (HelperStatusImpl)
                ((SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId)).getHelperStatusById(receiverId);
        // Deliver a notification
        LibState.getInstance()
                .getMeSharer()
                .deliverNotification(
                        DeRecStatusNotification.StandardNotificationType.LIST_SECRET_PROGRESS,
                        DeRecStatusNotification.NotificationSeverity.UNCLASSIFIED,
                        "Sending GetSecretIdsVersionsRequest",
                        (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId),
                        null,
                        hs);

        Derecmessage.DeRecMessage deRecMessage =
                createGetSecretIdsVersionsRequestMessage(senderId, receiverId, secretId);
        byte[] msgBytes = getPackagedBytes(
                receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), true, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    /**
     * Sends a GetSecretIdsVersionsResponseMessage
     *
     * @param senderId            DeRecIdentity of the message sender
     * @param receiverId          DeRecIdentity of the message receiver
     * @param secretId            SecretId this message is being sent in the context of
     * @param publicKeyId         publicKeyId of the message receiver
     * @param result              Handling status of the message
     * @param secretIdAndVersions Map of known secretIds and versions
     */
    public static void sendGetSecretIdsVersionsResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            int publicKeyId,
            ResultOuterClass.Result result,
            HashMap<DeRecSecret.Id, ArrayList<Integer>> secretIdAndVersions) {
        Logger staticLogger = LoggerFactory.getLogger(GetSecretIdsVersionsMessages.class.getName());

        staticLogger.debug("In sendGetSecretIdsVersionsResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createGetSecretIdsVersionsResponseMessage(
                senderId, receiverId, secretId, result, secretIdAndVersions);
        staticLogger.debug("Generated sendGetSecretIdsVersionsResponseMessage: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending sendGetSecretIdsVersionsResponseMessage ");
        byte[] msgBytes = getPackagedBytes(
                receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), false, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    /**
     * Handles a received GetSecretIdsVersionsRequest
     *
     * @param publicKeyId publicKeyId of the message receiver
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    SecretId the message was sent in the context of
     * @param message     The GetSecretIdsVersionsRequest message
     */
    public static void handleGetSecretIdsVersionsRequest(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            Secretidsversions.GetSecretIdsVersionsRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(GetSecretIdsVersionsMessages.class.getName());

        try {
            staticLogger.debug("In handleGetSecretIdsVersionsRequest");
            boolean found = false;
            HashMap<DeRecSecret.Id, ArrayList<Integer>> secretIdAndVersions = new HashMap<>();

            // Find the previous identities of the Sharer
            List<SharerStatusImpl> lostSharers =
                    LibState.getInstance().getMeHelper().getLostSharers(senderId.getPublicEncryptionKey());
            if (lostSharers == null) {
                staticLogger.info("Could not find lost sharer for " + senderId.getPublicEncryptionKey());
                LibState.getInstance().getMeHelper().printPublicKeyToLostSharerMap();
                found = false;
            } else {
                staticLogger.debug(
                        "Looked up publicKey " + senderId.getPublicEncryptionKey() + " and found " + lostSharers);
                // Now find all shares that this lost sharer had stored and harvest secretIds and versionNumbers from
                // these shares
                for (ShareImpl share :
                        (List<ShareImpl>) LibState.getInstance().getMeHelper().getShares()) {
                    for (SharerStatusImpl lostSharer : lostSharers) {
                        if (share.getSharer()
                                .getId()
                                .getPublicEncryptionKey()
                                .equals(lostSharer.getId().getPublicEncryptionKey())) {
                            DeRecSecret.Id sid = share.getSecretId();
                            if (!secretIdAndVersions.containsKey(sid)) {
                                secretIdAndVersions.put(sid, new ArrayList<>());
                                staticLogger.debug("Found previously stored secret "
                                        + Base64.getEncoder().encodeToString(sid.getBytes()));
                                found = true;
                            }
                            secretIdAndVersions.get(sid).add(share.getVersionNumber());
                        }
                    }
                }
            }

            // Deliver a notification to the application
            var uiResponse = (HelperImpl.NotificationResponse) LibState.getInstance()
                    .getMeHelper()
                    .deliverNotification(
                            DeRecHelper.Notification.StandardHelperNotificationType.LIST_SECRETS_INDICATION,
                            senderId,
                            secretId,
                            -1);

            boolean okToSend = false;
            if (found && uiResponse.getResult()) {
                okToSend = true;
            }
            staticLogger.debug("About to call sendGetSecretIdsVersionsResponseMessage");
            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(okToSend ? ResultOuterClass.StatusEnum.OK : ResultOuterClass.StatusEnum.FAIL)
                    .setMemo(okToSend ? "Found Shares" : "Shares not found")
                    .build();
            // Send the message
            GetSecretIdsVersionsMessages.sendGetSecretIdsVersionsResponseMessage(
                    receiverId,
                    senderId,
                    secretId,
                    LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(),
                    result,
                    okToSend ? secretIdAndVersions : new HashMap<>());
        } catch (Exception ex) {
            staticLogger.error("Exception in handleGetSecretIdsVersionsRequest", ex);
        }
    }

    /**
     * Handles a recevied GetSecretIdsVersionsResponse
     *
     * @param publicKeyId publicKeyId of the message sender
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    SecretId the message was sent in the context of
     * @param message     The GetSecretIdsVersionsResponseMessage
     */
    public static void handleGetSecretIdsVersionsResponse(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            Secretidsversions.GetSecretIdsVersionsResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(GetSecretIdsVersionsMessages.class.getName());

        try {
            staticLogger.debug("In handleGetSecretIdsVersionsResponse from " + senderId.getName());
            // Get HelperStatus from the senderId
            Optional<HelperStatusImpl> helperStatusOptional = (Optional<HelperStatusImpl>)
                    LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream()
                            .filter(hs -> hs.getId().getPublicEncryptionKey().equals(senderId.getPublicEncryptionKey()))
                            .findFirst();
            HelperStatusImpl helperStatus = helperStatusOptional.get();

            if (message.getResult().getStatus() != ResultOuterClass.StatusEnum.OK) {
                // Deliver a notification to the application that the status was not OK
                LibState.getInstance()
                        .getMeSharer()
                        .deliverNotification(
                                DeRecStatusNotification.StandardNotificationType.LIST_SECRET_FAILED,
                                DeRecStatusNotification.NotificationSeverity.ERROR,
                                "getSecretIdsVersionsResponse failed",
                                null,
                                null,
                                helperStatus);
                return;
            } else {
                // Deliver a notification to the application that the status was OK
                LibState.getInstance()
                        .getMeSharer()
                        .deliverNotification(
                                DeRecStatusNotification.StandardNotificationType.LIST_SECRET_AVAILABLE,
                                DeRecStatusNotification.NotificationSeverity.NORMAL,
                                "getSecIdsVersResponse received",
                                null,
                                null,
                                helperStatus);
            }

            for (Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList secretListItem :
                    message.getSecretListList()) {
                staticLogger.debug("Got secret: "
                        + Base64.getEncoder()
                                .encodeToString(secretListItem.getSecretId().toByteArray()));

                // Store what secretIds and versions the helper has
                LibState.getInstance()
                        .getMeSharer()
                        .getRecoveryContext()
                        .helperHasVersions(
                                new DeRecSecret.Id(secretListItem.getSecretId().toByteArray()),
                                helperStatus,
                                new ArrayList<>(secretListItem.getVersionsList()));

                // Deliver a notification to the application that a new secretId was found to recover
                LibState.getInstance()
                        .getMeSharer()
                        .deliverNotification(
                                DeRecStatusNotification.StandardNotificationType.RECOVERY_SECRET_SHARE_DISCOVERED,
                                DeRecStatusNotification.NotificationSeverity.NORMAL,
                                "Recoverable Secret/Share discovered: "
                                        + new DeRecSecret.Id(
                                                secretListItem.getSecretId().toByteArray()),
                                null,
                                null,
                                helperStatus);
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleGetSecretIdsVersionsResponse", ex);
        }
    }
}
