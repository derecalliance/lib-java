package org.derecalliance.derec.lib.impl;

import static org.derecalliance.derec.lib.impl.MessageParser.logger;
import static org.derecalliance.derec.lib.impl.MessageParser.printDeRecMessage;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Timestamp;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MessageFactory {

    /**
     * Creates a DeRecMessage containing a HelperMessageBody
     *
     * @param senderId      DeRecIdentity of the message sender
     * @param receiverId    DeRecIdentity of the message receiver
     * @param secretId      SecretId of the secret the message is being sent in the context of
     * @param messageSetter HelperMessageBody builder
     * @return DeRecMessage protobuf
     */
    static Derecmessage.DeRecMessage createHelperMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            Consumer<Derecmessage.DeRecMessage.HelperMessageBody.Builder> messageSetter) {

        Derecmessage.DeRecMessage.HelperMessageBody.Builder messageBodyBuilder =
                Derecmessage.DeRecMessage.HelperMessageBody.newBuilder();

        // Apply the specific message setting
        messageSetter.accept(messageBodyBuilder);

        Instant now = Instant.now();
        Timestamp timestamp = Timestamp.newBuilder()
                .setSeconds(now.getEpochSecond())
                .setNanos(now.getNano())
                .build();

        // Build the complete DeRecMessage
        return Derecmessage.DeRecMessage.newBuilder()
                .setProtocolVersionMajor(0)
                .setProtocolVersionMinor(9)
                .setTimestamp(timestamp)
                .setSender(ByteString.copyFrom(senderId.getPublicEncryptionKeyDigest()))
                .setReceiver(ByteString.copyFrom(receiverId.getPublicEncryptionKeyDigest()))
                .setSecretId(ByteString.copyFrom(secretId.getBytes()))
                .setMessageBodies(Derecmessage.DeRecMessage.MessageBodies.newBuilder()
                        .setHelperMessageBodies(Derecmessage.DeRecMessage.HelperMessageBodies.newBuilder()
                                .addHelperMessageBody(messageBodyBuilder.build())
                                .build())
                        .build())
                .build();
    }

    /**
     * Creates a DeRecMessage containing a SharerMessageBody
     *
     * @param senderId      DeRecIdentity of the message sender
     * @param receiverId    DeRecIdentity of the message receiver
     * @param secretId      SecretId of the secret the message is being sent in the context of
     * @param messageSetter SharerMessageBody builder
     * @return DeRecMessage protobuf
     */
    public static Derecmessage.DeRecMessage createSharerMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            Consumer<Derecmessage.DeRecMessage.SharerMessageBody.Builder> messageSetter) {

        Derecmessage.DeRecMessage.SharerMessageBody.Builder messageBodyBuilder =
                Derecmessage.DeRecMessage.SharerMessageBody.newBuilder();

        // Apply the specific message setting
        messageSetter.accept(messageBodyBuilder);

        Instant now = Instant.now();
        Timestamp timestamp = Timestamp.newBuilder()
                .setSeconds(now.getEpochSecond())
                .setNanos(now.getNano())
                .build();

        // Build the complete DeRecMessage
        return Derecmessage.DeRecMessage.newBuilder()
                .setProtocolVersionMajor(0)
                .setProtocolVersionMinor(9)
                .setTimestamp(timestamp)
                .setSender(ByteString.copyFrom(senderId.getPublicEncryptionKeyDigest()))
                .setReceiver(ByteString.copyFrom(receiverId.getPublicEncryptionKeyDigest()))
                .setSecretId(ByteString.copyFrom(secretId.getBytes()))
                .setMessageBodies(Derecmessage.DeRecMessage.MessageBodies.newBuilder()
                        .setSharerMessageBodies(Derecmessage.DeRecMessage.SharerMessageBodies.newBuilder()
                                .addSharerMessageBody(messageBodyBuilder.build())
                                .build())
                        .build())
                .build();
    }

    /**
     * Creates a DeRecMessage for PairRequestMessage
     */
    public static Derecmessage.DeRecMessage createPairRequestMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            Pair.SenderKind senderKind,
            String publicSignatureKey,
            String publicEncryptionKey,
            int publicKeyId,
            Communicationinfo.CommunicationInfo communicationInfo,
            long nonce,
            Parameterrange.ParameterRange parameterRange) {
        Pair.PairRequestMessage pairRequestMessage = Pair.PairRequestMessage.newBuilder()
                .setSenderKind(senderKind)
                .setPublicSignatureKey(publicSignatureKey)
                .setPublicEncryptionKey(publicEncryptionKey)
                .setPublicKeyId(publicKeyId)
                .setCommunicationInfo(communicationInfo)
                .setNonce(nonce)
                .setParameterRange(parameterRange)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId, receiverId, secretId, builder -> builder.setPairRequestMessage(pairRequestMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for PairResponseMessage
     */
    public static Derecmessage.DeRecMessage createPairResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            ResultOuterClass.Result result,
            Pair.SenderKind senderKind,
            String publicSignatureKey,
            Communicationinfo.CommunicationInfo communicationInfo,
            long nonce,
            Parameterrange.ParameterRange parameterRange) {
        Pair.PairResponseMessage pairResponseMessage = Pair.PairResponseMessage.newBuilder()
                .setResult(result)
                .setSenderKind(senderKind)
                .setPublicSignatureKey(publicSignatureKey)
                .setCommunicationInfo(communicationInfo)
                .setNonce(nonce)
                .setParameterRange(parameterRange)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(
                senderId, receiverId, secretId, builder -> builder.setPairResponseMessage(pairResponseMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for UnpairRequestMessage
     */
    public static Derecmessage.DeRecMessage createUnpairRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, String memo) {
        Unpair.UnpairRequestMessage unpairRequestMessage =
                Unpair.UnpairRequestMessage.newBuilder().setMemo(memo).build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId, receiverId, secretId, builder -> builder.setUnpairRequestMessage(unpairRequestMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for UnpairResponseMessage
     */
    public static Derecmessage.DeRecMessage createUnpairResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, ResultOuterClass.Result result) {
        Unpair.UnpairResponseMessage unpairResponseMessage =
                Unpair.UnpairResponseMessage.newBuilder().setResult(result).build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(
                senderId, receiverId, secretId, builder -> builder.setUnpairResponseMessage(unpairResponseMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for StoreShareRequestMessage
     */
    public static Derecmessage.DeRecMessage createStoreShareRequestMessageWithoutShare(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, List<Integer> keepList) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());

        staticLogger.debug("in createStoreShareRequestMessageWithoutShare, keeplist = " + keepList);
        for (Integer v : keepList) {
            staticLogger.debug("createStoreShareRequestMessageWithoutShare Keeplist item: " + v);
        }

        Storeshare.StoreShareRequestMessage storeShareRequestMessage = Storeshare.StoreShareRequestMessage.newBuilder()
                .addAllKeepList(keepList)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setStoreShareRequestMessage(storeShareRequestMessage));
        printDeRecMessage(deRecMessage, "Sending messsage  - storeShareRequestMessage with empty share");
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for StoreShareResponseMessage
     */
    public static Derecmessage.DeRecMessage createStoreShareRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, ShareImpl share) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());

        SecretImpl secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
        List<Integer> keepList = secret.versionsMap.keySet().stream().toList();

        Storeshare.StoreShareRequestMessage.Builder storeShareRequestMessageBuilder =
                Storeshare.StoreShareRequestMessage.newBuilder();

        if (share != null) {
            storeShareRequestMessageBuilder
                    .setShare(ByteString.copyFrom(share.getCommittedDeRecShare().toByteArray()))
                    .setShareAlgorithm(1)
                    .setVersion(share.getVersionNumber());
            staticLogger.debug("createStoreShareRequestMessage sending FULL share");
        } else {
            staticLogger.debug("createStoreShareRequestMessage sending BLANK share");
        }
        Storeshare.StoreShareRequestMessage storeShareRequestMessage =
                storeShareRequestMessageBuilder.addAllKeepList(keepList).build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setStoreShareRequestMessage(storeShareRequestMessage));
        printDeRecMessage(deRecMessage, "Sending messsage ");
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for StoreShareResponseMessage
     */
    public static Derecmessage.DeRecMessage createStoreShareResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            ResultOuterClass.Result result,
            int versionNumber) {
        Storeshare.StoreShareResponseMessage storeShareResponseMessage =
                Storeshare.StoreShareResponseMessage.newBuilder()
                        .setResult(result)
                        .setVersion(versionNumber)
                        .build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setStoreShareResponseMessage(storeShareResponseMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for VerifyShareRequestMessage
     */
    public static Derecmessage.DeRecMessage createVerifyShareRequestMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            int versionNumber,
            byte[] nonce) {
        Verify.VerifyShareRequestMessage verifyShareRequestMessage = Verify.VerifyShareRequestMessage.newBuilder()
                .setVersion(versionNumber)
                .setNonce(ByteString.copyFrom(nonce))
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setVerifyShareRequestMessage(verifyShareRequestMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for VerifyShareResponseMessage
     */
    public static Derecmessage.DeRecMessage createVerifyShareResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            ResultOuterClass.Result result,
            int versionNumber,
            byte[] nonce,
            byte[] hash) {
        Verify.VerifyShareResponseMessage verifyShareResponseMessage = Verify.VerifyShareResponseMessage.newBuilder()
                .setResult(result)
                .setVersion(versionNumber)
                .setNonce(ByteString.copyFrom(nonce))
                .setHash(ByteString.copyFrom(hash))
                .build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setVerifyShareResponseMessage(verifyShareResponseMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for GetSecretIdsVersionsRequestMessage
     */
    public static Derecmessage.DeRecMessage createGetSecretIdsVersionsRequestMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId) {
        Secretidsversions.GetSecretIdsVersionsRequestMessage getSecretIdsVersionsRequestMessage =
                Secretidsversions.GetSecretIdsVersionsRequestMessage.newBuilder()
                        .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setGetSecretIdsVersionsRequestMessage(getSecretIdsVersionsRequestMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for GetSecretIdsVersionsResponseMessage
     */
    public static Derecmessage.DeRecMessage createGetSecretIdsVersionsResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            ResultOuterClass.Result result,
            HashMap<DeRecSecret.Id, ArrayList<Integer>> secretIdAndVersions) {
        Secretidsversions.GetSecretIdsVersionsResponseMessage.Builder getSecretIdsVersionsResponseMessageBuilder =
                Secretidsversions.GetSecretIdsVersionsResponseMessage.newBuilder()
                        .setResult(result);
        for (DeRecSecret.Id sid : secretIdAndVersions.keySet()) {
            Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList.Builder oneSecretBuilder =
                    Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList.newBuilder()
                            .setSecretId(ByteString.copyFrom(sid.getBytes()));
            for (Integer versionNumber : secretIdAndVersions.get(sid)) {
                oneSecretBuilder.addVersions(versionNumber);
            }
            Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList oneSecret = oneSecretBuilder.build();
            getSecretIdsVersionsResponseMessageBuilder.addSecretList(oneSecret);
        }

        Secretidsversions.GetSecretIdsVersionsResponseMessage getSecretIdsVersionsResponseMessage =
                getSecretIdsVersionsResponseMessageBuilder.build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(
                senderId,
                receiverId,
                secretId,
                builder -> builder.setGetSecretIdsVersionsResponseMessage(getSecretIdsVersionsResponseMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for GetShareRequestMessage
     */
    public static Derecmessage.DeRecMessage createGetShareRequestMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id currentSecretId,
            DeRecSecret.Id recoveringSecretId,
            int versionNumber) {
        Getshare.GetShareRequestMessage getShareRequestMessage = Getshare.GetShareRequestMessage.newBuilder()
                .setSecretId(ByteString.copyFrom(recoveringSecretId.getBytes()))
                .setShareVersion(versionNumber)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId,
                receiverId,
                currentSecretId,
                builder -> builder.setGetShareRequestMessage(getShareRequestMessage));
        return deRecMessage;
    }

    /**
     * Creates a DeRecMessage for GetShareResponseMessage
     */
    public static Derecmessage.DeRecMessage createGetShareResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id currentSecretId,
            DeRecSecret.Id recoveringSecretId,
            ResultOuterClass.Result result,
            Storeshare.CommittedDeRecShare committedDeRecShare) {
        Getshare.GetShareResponseMessage getShareResponseMessage = Getshare.GetShareResponseMessage.newBuilder()
                .setResult(result)
                .setCommittedDeRecShare(committedDeRecShare)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(
                senderId,
                receiverId,
                currentSecretId,
                builder -> builder.setGetShareResponseMessage(getShareResponseMessage));
        return deRecMessage;
    }

    /**
     * Prepares the message to be sent over the wire
     *
     * @param publicKeyId            public key id of the message recipient
     * @param serializedDeRecMessage protobuf-serialized DeRecMessage
     * @param isSharer               True if message sender is a sharer. False otherwise.
     * @param secretId               secret id corresponding to the message
     * @param receiverId             DeRecIdentity of the message receiver
     * @param shouldSign             whether the message should be signed
     * @return byte[] containing the complete message to be sent
     */
    // TODO: remove shouldSign flag since all outgoing messages are signed-then-encrypted
    public static byte[] getPackagedBytes(
            int publicKeyId,
            byte[] serializedDeRecMessage,
            boolean isSharer,
            DeRecSecret.Id secretId,
            DeRecIdentity receiverId,
            boolean shouldSign) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());

        try {
            Derecmessage.DeRecMessage msg = Derecmessage.DeRecMessage.parseFrom(serializedDeRecMessage);
            printDeRecMessage(msg, "Sending ");
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }

        String privateSignatureKey = "";
        String publicEncryptionKey = "";

        // Find our privateSignatureKey, and receiver's publicEncryptionKey.
        // If we are the sharer, find the publicEncryptionKey of the helper.
        // And if we are the helper, find the publicEncryptionKey of the sharer
        if (isSharer) {
            SecretImpl secret =
                    (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
            privateSignatureKey = secret.getLibId().getSignaturePrivateKey();
            Optional<? extends DeRecHelperStatus> helperStatusOptional =
                    LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream()
                            .filter(hs -> hs.getId().equals(receiverId))
                            .findFirst();
            if (helperStatusOptional.isPresent()) {
                publicEncryptionKey = helperStatusOptional.get().getId().getPublicEncryptionKey();
            } else {
                staticLogger.debug("Could not find helper status of receiver: " + receiverId.getName());
                return null;
            }
        } else {
            privateSignatureKey =
                    LibState.getInstance().getMeHelper().getMyLibId().getSignaturePrivateKey();
            Optional<? extends SharerStatusImpl> sharerStatusOptional =
                    LibState.getInstance().getMeHelper().getSharers().stream()
                            .filter(ss -> ss.getId().equals(receiverId))
                            .findFirst();
            if (sharerStatusOptional.isPresent()) {
                publicEncryptionKey = sharerStatusOptional.get().getId().getPublicEncryptionKey();
            } else {
                System.out.println("Could not find sharer status of receiver: " + receiverId.getName());
                return null;
            }
        }

        staticLogger.debug("About to signThenEncrypt with privateSignatureKey=" + privateSignatureKey + ", "
                + "publicEncryptionKey=" + publicEncryptionKey);
        byte[] signedBytes = LibState.getInstance()
                .getDerecCryptoImpl()
                .signThenEncrypt(
                        serializedDeRecMessage,
                        Base64.getDecoder().decode(privateSignatureKey),
                        Base64.getDecoder().decode(publicEncryptionKey));

        byte[] withPublicKeyId = ByteBuffer.allocate(4 + signedBytes.length)
                .putInt(publicKeyId)
                .put(signedBytes)
                .array();
        return withPublicKeyId;
    }

    /**
     * Parses a received message
     *
     * @param receivedMessage byte[] containing the received message
     * @return Whether parsing the message was successful
     */
    public static boolean parseAndProcessPackagedBytes(byte[] receivedMessage) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());
        try {
            ByteBuffer buffer = ByteBuffer.wrap(receivedMessage);
            // Extract the publicKeyId from the first 4 bytes
            int extractedPublicKeyId = buffer.getInt();
            LibIdentity myIdentity =
                    LibState.getInstance().publicKeyIdToLibIdentityMap.get(extractedPublicKeyId);
            if (myIdentity == null) {
                staticLogger.debug(
                        "Dropping message - Received a message with unknown publicKeyId: " + extractedPublicKeyId);
                LibState.getInstance().printPublicKeyIdToIdentityMap();
                return false;
            }

            // Process the remaining bytes now that we have extracted the publicKeyId
            byte[] remainingBytes = new byte[receivedMessage.length - 4];
            System.arraycopy(receivedMessage, 4, remainingBytes, 0, remainingBytes.length);

            Derecmessage.DeRecMessage derecmessage = null;
            byte[] decryptedMsg = LibState.getInstance()
                    .getDerecCryptoImpl()
                    .decrypt(remainingBytes, Base64.getDecoder().decode(myIdentity.getEncryptionPrivateKey()));
            int signatureLength = 64;
            byte[] signatureBytes = new byte[signatureLength];
            byte[] msgToParse = new byte[decryptedMsg.length - signatureLength];
            // Copy the first 64 bytes to signatureBytes
            System.arraycopy(decryptedMsg, 0, signatureBytes, 0, signatureLength);
            // Copy the remaining bytes to msgToParse
            System.arraycopy(decryptedMsg, signatureLength, msgToParse, 0, msgToParse.length);
            derecmessage = Derecmessage.DeRecMessage.parseFrom(msgToParse);

            String senderSignaturePublicKey = "";
            // For PairRequest and PairResponse messages, the sender's signature key should be extracted from the
            // received message
            if (derecmessage.hasMessageBodies()
                    && derecmessage.getMessageBodies().hasSharerMessageBodies()
                    && derecmessage
                            .getMessageBodies()
                            .getSharerMessageBodies()
                            .getSharerMessageBody(0)
                            .hasPairRequestMessage()) {
                // get the sharer's public signature key
                senderSignaturePublicKey = derecmessage
                        .getMessageBodies()
                        .getSharerMessageBodies()
                        .getSharerMessageBody(0)
                        .getPairRequestMessage()
                        .getPublicSignatureKey();
            } else if (derecmessage.hasMessageBodies()
                    && derecmessage.getMessageBodies().hasHelperMessageBodies()
                    && derecmessage
                            .getMessageBodies()
                            .getHelperMessageBodies()
                            .getHelperMessageBody(0)
                            .hasPairResponseMessage()) {
                // get the helper's public signature key
                senderSignaturePublicKey = derecmessage
                        .getMessageBodies()
                        .getHelperMessageBodies()
                        .getHelperMessageBody(0)
                        .getPairResponseMessage()
                        .getPublicSignatureKey();
            } else {
                // get the message sender's public signature key by referencing messageHashToIdentityMap
                DeRecIdentity senderDeRecIdentity = LibState.getInstance()
                        .queryMessageHashAndSecretIdToIdentity(
                                derecmessage.getSender(),
                                new DeRecSecret.Id(derecmessage.getSecretId().toByteArray()));
                senderSignaturePublicKey = senderDeRecIdentity.getPublicSignatureKey();
                logger.debug("Sender " + senderDeRecIdentity.getName() + " public signature key is "
                        + senderSignaturePublicKey);
            }
            byte[] verificationResult = LibState.getInstance()
                    .getDerecCryptoImpl()
                    .verify(msgToParse, signatureBytes, Base64.getDecoder().decode(senderSignaturePublicKey));
            staticLogger.debug("verify returned: " + verificationResult);
            // TODO: check what Cryptography library is returning and drop the message if verification fails.

            MessageParser mp = new MessageParser();
            mp.parseMessage(extractedPublicKeyId, derecmessage);
            return true;
        } catch (Exception ex) {
            staticLogger.error("Exception in parseAndProcessPackagedBytes", ex);
            return false;
        }
    }
}
