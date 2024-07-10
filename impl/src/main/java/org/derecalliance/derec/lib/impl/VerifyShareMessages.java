package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Share;
//import org.derecalliance.derec.lib.Version;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.ResultOuterClass;
import org.derecalliance.derec.protobuf.Verify;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

//import static org.derecalliance.derec.lib.api.MessageFactory.*;
//import static org.derecalliance.derec.lib.api.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.MessageFactory.createVerifyShareRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

public class VerifyShareMessages {
    public static void sendVerifyShareRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            int versionNumber, byte[] nonce) {
        Derecmessage.DeRecMessage deRecMessage = createVerifyShareRequestMessage(senderId, receiverId, secretId,
                versionNumber, nonce);
        byte[] msgBytes = getPackagedBytes(receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), true, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }

    public static void sendVerifyShareResponseMessage(
        DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, int publicKeyId,
            ResultOuterClass.Result result, int versionNumber,byte[] nonce, byte[] hash) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());
        staticLogger.debug("In sendVerifyShareResponseMessage");
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createVerifyShareResponseMessage(
                senderId, receiverId, secretId,
                result, versionNumber, nonce, hash);
        staticLogger.debug("Generated sendVerifyShareResponseMessage: ");
        MessageParser.printDeRecMessage(deRecMessage, "Sending sendVerifyShareResponseMessage ");
        byte[] msgBytes = getPackagedBytes(receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), false, secretId, receiverId, true);
        sendHttpRequest(receiverId.getAddress(), msgBytes);
    }


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
            staticLogger.error("Exception in calculateVerificationHash", ex);
            throw new RuntimeException("Exception in calculateVerificationHash");

        }
    }

    public static void handleVerifyShareRequest(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                               Verify.VerifyShareRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());

        try {
            staticLogger.debug("In handleVerifyShareRequest");
//            SharerStatus sharerStatus = new SharerStatus(senderId);
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
            byte [] hash = share == null ? new byte[]{} : calculateVerificationHash(share.getCommittedDeRecShare().toByteArray(), nonce);

//            ShareImpl share = new ShareImpl(secretId, message.getVersion(), sharerStatus, message.getShare().toByteArray());
//            LibState.getInstance().getMeHelper().addShare(sharerStatus, secretId, message.getVersion(), share);
//            staticLogger.debug("Added ShareImpl");
//            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
//                    .setStatus(ResultOuterClass.StatusEnum.OK)
//                    .setMemo("Thank you for storing the share with me!")
//                    .build();
            staticLogger.debug("About to call sendVerifyShareResponseMessage");
            VerifyShareMessages.sendVerifyShareResponseMessage(receiverId, sharerStatus.getId(),
                    secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result,
                    versionNumber, nonce, hash);
        } catch (Exception ex) {
            staticLogger.error("Exception in handleVerifyShareRequest", ex);
        }
    }


    public static void handleVerifyShareResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                                 Verify.VerifyShareResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(VerifyShareMessages.class.getName());

        try {
            staticLogger.debug("In handleVerifyShareResponse from " + senderId.getName());
            var secret =  (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            staticLogger.debug("In handleVerifyShareResponse - Secret is: " + secret);
            int versionNumber = message.getVersion();
            VersionImpl version = secret.getVersionByNumber(versionNumber);
            if (secret != null && version != null) {
                byte[] nonce = message.getNonce().toByteArray();
                byte[] hash = message.getHash().toByteArray();

                version.handleVerificationResponse(senderId, nonce, hash, versionNumber);
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handleVerifyShareResponse", ex);
        }
    }
}
