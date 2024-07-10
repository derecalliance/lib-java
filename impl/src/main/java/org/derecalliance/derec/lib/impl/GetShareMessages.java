package org.derecalliance.derec.lib.impl;

import static org.derecalliance.derec.lib.impl.MessageFactory.createGetShareRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

import java.util.Base64;
import java.util.Optional;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GetShareMessages {
    public static void sendGetShareRequestMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id currentSecretId,
            DeRecSecret.Id recoveringSecretId,
            int publicKeyId,
            int shareVersion) {
        Logger staticLogger = LoggerFactory.getLogger(GetShareMessages.class.getName());
        Derecmessage.DeRecMessage deRecMessage =
                createGetShareRequestMessage(senderId, receiverId, currentSecretId, recoveringSecretId, shareVersion);
        byte[] msgBytes = getPackagedBytes(
                receiverId.getPublicEncryptionKeyId(),
                deRecMessage.toByteArray(),
                true,
                currentSecretId,
                receiverId,
                true);
        staticLogger.debug("***** In sendGetShareRequestMessage sending GetShareRequest to " + receiverId.getName()
                + " for version " + shareVersion);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void sendGetShareResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id currentSecretId,
            DeRecSecret.Id recoveringSecretId,
            int publicKeyId,
            ResultOuterClass.Result result,
            Storeshare.CommittedDeRecShare committedDeRecShare) {
        Logger staticLogger = LoggerFactory.getLogger(GetShareMessages.class.getName());
        staticLogger.debug("In sendGetShareResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createGetShareResponseMessage(
                senderId, receiverId, currentSecretId, recoveringSecretId, result, committedDeRecShare);
        staticLogger.debug("Generated response: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
        byte[] msgBytes = getPackagedBytes(
                receiverId.getPublicEncryptionKeyId(),
                deRecMessage.toByteArray(),
                false,
                currentSecretId,
                receiverId,
                true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void handleGetShareRequest(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id currentSecretId,
            Getshare.GetShareRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(GetShareMessages.class.getName());

        try {
            LibState.getInstance()
                    .getMeHelper()
                    .deliverNotification(
                            DeRecHelper.Notification.StandardHelperNotificationType.RECOVER_SECRET_INDICATION,
                            senderId,
                            null,
                            message.getShareVersion());
            // Process PairRequestMessage
            staticLogger.debug("In handleGetShareRequest");
            //            byte[] secretIdBytes = secretId.getBytes();//message.getSecretId().toByteArray();
            DeRecSecret.Id recoveringSecretId =
                    new DeRecSecret.Id(message.getSecretId().toByteArray());
            int versionNumber = message.getShareVersion();
            SharerStatusImpl sharerStatus = new SharerStatusImpl(senderId);
            staticLogger.debug("In handleGetShareRequest for sharer key: "
                    + sharerStatus.getId().getPublicEncryptionKey() + ", " + ", Current Sec id: "
                    + Base64.getEncoder().encodeToString(currentSecretId.getBytes()) + " or " + currentSecretId
                    + ", Recovering Sec id: "
                    + Base64.getEncoder().encodeToString(recoveringSecretId.getBytes()) + " " + "or "
                    + recoveringSecretId + ", Ver: "
                    + versionNumber);

            //            (Optional<ShareImpl>)
            staticLogger.debug("recdCommittedShares: "
                    + LibState.getInstance().getMeHelper().sharesToString());
            // TODO: Add the check that is commented below. This should make sure that the we look for the original
            //  sharer's public key. The recovering sharer's public key should be mapped to the original sharer's
            //  public key in LibState after receiving a Pairing Request.
            Optional<ShareImpl> shareToReturn =
                    (Optional<ShareImpl>) LibState.getInstance().getMeHelper().getShares().stream()
                            //    commented because the sharer's public key has changed when they are recovering...
                            //           .filter(s -> s
                            //    .getSharer().getId().getPublicEncryptionKey().equals(senderId
                            //    .getPublicEncryptionKey()))
                            .filter(s -> s.getSecretId().equals(recoveringSecretId))
                            .filter(s -> s.getVersions().get(0) == versionNumber)
                            .findFirst();

            ResultOuterClass.Result result;
            //            CommittedDeRecShare committedDeRecShare = null;
            if (shareToReturn.isPresent()) {
                staticLogger.debug("shareToReturn is present: from "
                        + shareToReturn.get().getSharer().getId().getName());

                //                try {
                //                    CommittedDeRecShare cds =
                //                            new
                // CommittedDeRecShare(Storeshare.CommittedDeRecShare.parseFrom(shareToReturn.get().getCommittedDeRecShareBytes()));
                //                    staticLogger.debug("In handleGetShareRequest Committed DeRecShare  is: " +
                // cds.toString());
                //                } catch (InvalidProtocolBufferException ex) {
                //                    staticLogger.error("Exception in trying to parse the committed derec share");
                //                    ex.printStackTrace();
                //                }

                result = ResultOuterClass.Result.newBuilder()
                        .setStatus(ResultOuterClass.StatusEnum.OK)
                        .build();
                //                committedDeRecShare = new CommittedDeRecShare(
                //
                // Storeshare.CommittedDeRecShare.parseFrom(ByteString.copyFrom(shareToReturn.get().getCommittedDeRecShareBytes())));

            } else {
                staticLogger.debug("Oops. I couldn't find a shareToReturn");
                result = ResultOuterClass.Result.newBuilder()
                        .setStatus(ResultOuterClass.StatusEnum.FAIL)
                        .build();
            }
            staticLogger.debug("About to call sendGetShareResponseMessage, committedDeRecShare is: " + shareToReturn);
            // Send GetShareResponse
            GetShareMessages.sendGetShareResponseMessage(
                    receiverId,
                    senderId,
                    currentSecretId,
                    recoveringSecretId,
                    LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(),
                    result,
                    shareToReturn.get().getCommittedDeRecShare());
        } catch (Exception ex) {
            staticLogger.error("Exception in handleGetShareRequest", ex);
        }
    }

    public static void handleGetShareResponse(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            Getshare.GetShareResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(GetShareMessages.class.getName());

        try {
            staticLogger.debug("In handleGetShareResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            staticLogger.debug("In handleGetShareResponse - Secret is: " + secret.getDescription());
            staticLogger.debug("Result: " + message.getResult().getStatus().toString());
            //            CommittedDeRecShare committedDeRecShare = new
            // CommittedDeRecShare(message.getCommittedDeRecShare());
            Storeshare.CommittedDeRecShare committedDeRecShare = message.getCommittedDeRecShare();
            Storeshare.DeRecShare deRecShare = Storeshare.DeRecShare.parseFrom(
                    message.getCommittedDeRecShare().getDeRecShare());
            staticLogger.debug("Version: " + deRecShare.getVersion());
            Optional<HelperStatusImpl> helperStatusOptional = (Optional<HelperStatusImpl>)
                    LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream()
                            .filter(hs -> hs.getId().getPublicEncryptionKey().equals(senderId.getPublicEncryptionKey()))
                            .findFirst();
            if (!helperStatusOptional.isPresent()) {
                staticLogger.debug("Could not find helper status for sender: " + senderId.getName());
                return;
            }

            int versionNumber = deRecShare.getVersion();
            VersionImpl fakeVersion = new VersionImpl(secret, new byte[] {}, versionNumber);

            LibState.getInstance()
                    .getMeSharer()
                    .deliverNotification(
                            DeRecStatusNotification.StandardNotificationType.RECOVERY_PROGRESS,
                            DeRecStatusNotification.NotificationSeverity.UNCLASSIFIED,
                            "Retrieved share",
                            secret,
                            fakeVersion,
                            helperStatusOptional.get());

            boolean success = LibState.getInstance()
                    .getMeSharer()
                    .getRecoveryContext()
                    .saveRetrievedCommittedDeRecShare(
                            secretId, versionNumber, helperStatusOptional.get(), committedDeRecShare);
            if (success) {
                DeRecSecret.Id recoveredSecretId =
                        new DeRecSecret.Id(deRecShare.getSecretId().toByteArray());
                SecretImpl recoveredSecret = (SecretImpl)
                        LibState.getInstance().getMeSharer().getRecoveredState().getSecret(recoveredSecretId);

                staticLogger.debug("Sending RECOVERY_COMPLETE notification");
                staticLogger.debug("  for secret: " + recoveredSecret.getDescription() + ", version: "
                        + recoveredSecret.getVersionByNumber(versionNumber).getVersionNumber());
                LibState.getInstance()
                        .getMeSharer()
                        .deliverNotification(
                                DeRecStatusNotification.StandardNotificationType.RECOVERY_COMPLETE,
                                DeRecStatusNotification.NotificationSeverity.NORMAL,
                                "Recovery complete",
                                recoveredSecret,
                                recoveredSecret.getVersionByNumber(versionNumber),
                                null);
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleGetShareResponse", ex);
        }
    }
}
