package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.api.DeRecMessage;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Timestamp;
//import org.derecalliance.derec.lib.Share;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

import static org.derecalliance.derec.lib.impl.MessageParser.logger;
import static org.derecalliance.derec.lib.impl.MessageParser.printDeRecMessage;

class MessageFactory {

    public class ParsedResult {
        final byte[] decryptedMessage;
        final boolean onlyAcceptPairingMessages;

        public ParsedResult(byte[] decryptedMessage, boolean onlyAcceptPairingMessages) {
            this.decryptedMessage = decryptedMessage;
            this.onlyAcceptPairingMessages = onlyAcceptPairingMessages;
        }
    }

     static Derecmessage.DeRecMessage createHelperMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
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

        // Build the complete message
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
    public static Derecmessage.DeRecMessage createSharerMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
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

        // Build the complete message
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

    public static Derecmessage.DeRecMessage createPairRequestMessage(DeRecIdentity senderId, DeRecIdentity receiverId
            , DeRecSecret.Id secretId, Pair.SenderKind senderKind, String publicSignatureKey, String publicEncryptionKey, int publicKeyId, Communicationinfo.CommunicationInfo communicationInfo, long nonce, Parameterrange.ParameterRange parameterRange ) {
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
                senderId, receiverId, secretId,
                builder -> builder.setPairRequestMessage(pairRequestMessage)
        );
        return deRecMessage;
    }

    public static Derecmessage.DeRecMessage createPairResponseMessage(
            DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId, ResultOuterClass.Result result,
            Pair.SenderKind senderKind, String publicSignatureKey,
            Communicationinfo.CommunicationInfo communicationInfo, long nonce,
            Parameterrange.ParameterRange parameterRange ) {
        Pair.PairResponseMessage pairResponseMessage =
                Pair.PairResponseMessage.newBuilder()
                .setResult(result)
                .setSenderKind(senderKind)
                .setPublicSignatureKey(publicSignatureKey)
                .setCommunicationInfo(communicationInfo)
                .setNonce(nonce)
                .setParameterRange(parameterRange)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, secretId,
                builder -> builder.setPairResponseMessage(pairResponseMessage)
        );
        return deRecMessage;
    }

    // Unpair
    public static Derecmessage.DeRecMessage createUnpairRequestMessage(DeRecIdentity senderId,
                                                                           DeRecIdentity receiverId,
                                                                       DeRecSecret.Id secretId, String memo) {
        Unpair.UnpairRequestMessage unpairRequestMessage =  Unpair.UnpairRequestMessage.newBuilder()
                .setMemo(memo)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId, receiverId, secretId,
                builder -> builder.setUnpairRequestMessage(unpairRequestMessage)
        );
        return deRecMessage;
    }

     public static Derecmessage.DeRecMessage createUnpairResponseMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
             ResultOuterClass.Result result) {
         Unpair.UnpairResponseMessage unpairResponseMessage =
                 Unpair.UnpairResponseMessage.newBuilder()
                         .setResult(result)
                         .build();

         Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, secretId,
                 builder -> builder.setUnpairResponseMessage(unpairResponseMessage)
         );
         return deRecMessage;
     }

    // Store share
    public static Derecmessage.DeRecMessage createStoreShareRequestMessageWithoutShare(DeRecIdentity senderId,
                                                                           DeRecIdentity receiverId,
                                                                           DeRecSecret.Id secretId, List<Integer> keepList) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());

        staticLogger.debug("in createStoreShareRequestMessageWithoutShare, keeplist = " + keepList);
        for (Integer v : keepList) {
            staticLogger.debug("createStoreShareRequestMessageWithoutShare Keeplist item: " + v);
        }

        Storeshare.StoreShareRequestMessage storeShareRequestMessage =  Storeshare.StoreShareRequestMessage.newBuilder()
                .addAllKeepList(keepList)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId, receiverId, secretId,
                builder -> builder.setStoreShareRequestMessage(storeShareRequestMessage)
        );
        printDeRecMessage(deRecMessage, "Sending messsage  - storeShareRequestMessage with empty share");
        return deRecMessage;
    }

    public static Derecmessage.DeRecMessage createStoreShareRequestMessage(DeRecIdentity senderId,
                                                                         DeRecIdentity receiverId,
                                                                           DeRecSecret.Id secretId, ShareImpl share) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());

        SecretImpl secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
        List<Integer> keepList = secret.versionsMap.keySet().stream().toList();

//        Storeshare.StoreShareRequestMessage storeShareRequestMessage =  Storeshare.StoreShareRequestMessage.newBuilder()
//                .setShare(ByteString.copyFrom(share.getCommittedDeRecShare().toByteArray()))
//                .setShareAlgorithm(1)
//                .setVersion(share.getVersionNumber())
//                .addAllKeepList(keepList)
//                .build();

        Storeshare.StoreShareRequestMessage.Builder storeShareRequestMessageBuilder =  Storeshare.StoreShareRequestMessage.newBuilder();

        if (share != null) {
            storeShareRequestMessageBuilder
                .setShare(ByteString.copyFrom(share.getCommittedDeRecShare().toByteArray()))
                .setShareAlgorithm(1)
                .setVersion(share.getVersionNumber());
            staticLogger.debug("createStoreShareRequestMessage sending FULL share");
        } else {
            staticLogger.debug("createStoreShareRequestMessage sending BLANK share");
        }
        Storeshare.StoreShareRequestMessage storeShareRequestMessage = storeShareRequestMessageBuilder
                .addAllKeepList(keepList)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId, receiverId, secretId,
                builder -> builder.setStoreShareRequestMessage(storeShareRequestMessage)
        );
        printDeRecMessage(deRecMessage, "Sending messsage ");
        return deRecMessage;
    }

     public static Derecmessage.DeRecMessage createStoreShareResponseMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
             ResultOuterClass.Result result, int versionNumber) {
         Storeshare.StoreShareResponseMessage storeShareResponseMessage =
                 Storeshare.StoreShareResponseMessage.newBuilder()
                         .setResult(result)
                         .setVersion(versionNumber)
                         .build();

         Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, secretId,
                 builder -> builder.setStoreShareResponseMessage(storeShareResponseMessage)
         );
         return deRecMessage;
     }


     // Verify share
     public static Derecmessage.DeRecMessage createVerifyShareRequestMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId,DeRecSecret.Id secretId,
             int versionNumber, byte[] nonce) {
         Verify.VerifyShareRequestMessage verifyShareRequestMessage =  Verify.VerifyShareRequestMessage.newBuilder()
                 .setVersion(versionNumber)
                 .setNonce(ByteString.copyFrom(nonce))
                 .build();

         Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                 senderId, receiverId, secretId,
                 builder -> builder.setVerifyShareRequestMessage(verifyShareRequestMessage)
         );
         return deRecMessage;
     }
     public static Derecmessage.DeRecMessage createVerifyShareResponseMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
             ResultOuterClass.Result result, int versionNumber, byte[] nonce, byte[] hash) {
         Verify.VerifyShareResponseMessage verifyShareResponseMessage =
                 Verify.VerifyShareResponseMessage.newBuilder()
                         .setResult(result)
                         .setVersion(versionNumber)
                         .setNonce(ByteString.copyFrom(nonce))
                         .setHash(ByteString.copyFrom(hash))
                         .build();

         Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, secretId,
                 builder -> builder.setVerifyShareResponseMessage(verifyShareResponseMessage)
         );
         return deRecMessage;
     }



     // Get Secret Ids Versions
     public static Derecmessage.DeRecMessage createGetSecretIdsVersionsRequestMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId,DeRecSecret.Id secretId) {
         Secretidsversions.GetSecretIdsVersionsRequestMessage getSecretIdsVersionsRequestMessage =
                 Secretidsversions.GetSecretIdsVersionsRequestMessage.newBuilder()
                 .build();

         Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                 senderId, receiverId, secretId,
                 builder -> builder.setGetSecretIdsVersionsRequestMessage(getSecretIdsVersionsRequestMessage)
         );
         return deRecMessage;
     }
     public static Derecmessage.DeRecMessage createGetSecretIdsVersionsResponseMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
             ResultOuterClass.Result result, HashMap<DeRecSecret.Id, ArrayList<Integer>> secretIdAndVersions) {
         Secretidsversions.GetSecretIdsVersionsResponseMessage.Builder getSecretIdsVersionsResponseMessageBuilder =
                 Secretidsversions.GetSecretIdsVersionsResponseMessage.newBuilder()
                         .setResult(result);
         for (DeRecSecret.Id sid : secretIdAndVersions.keySet()) {
             Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList.Builder oneSecretBuilder =
                     Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList.newBuilder()
                     .setSecretId(ByteString.copyFrom(sid.getBytes()));
             for (Integer versionNumber: secretIdAndVersions.get(sid)) {
                 oneSecretBuilder.addVersions(versionNumber);
             }
             Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList oneSecret =
                     oneSecretBuilder.build();
             getSecretIdsVersionsResponseMessageBuilder.addSecretList(oneSecret);
         }

         Secretidsversions.GetSecretIdsVersionsResponseMessage getSecretIdsVersionsResponseMessage =
                 getSecretIdsVersionsResponseMessageBuilder.build();

         Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, secretId,
                 builder -> builder.setGetSecretIdsVersionsResponseMessage(getSecretIdsVersionsResponseMessage)
         );
         return deRecMessage;
     }


     // Verify share
     public static Derecmessage.DeRecMessage createGetShareRequestMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId,DeRecSecret.Id currentSecretId,
             DeRecSecret.Id recoveringSecretId,
             int versionNumber) {
         Getshare.GetShareRequestMessage getShareRequestMessage =  Getshare.GetShareRequestMessage.newBuilder()
                 .setSecretId(ByteString.copyFrom(recoveringSecretId.getBytes()))
                 .setShareVersion(versionNumber)
                 .build();

         Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                 senderId, receiverId, currentSecretId,
                 builder -> builder.setGetShareRequestMessage(getShareRequestMessage)
         );
         return deRecMessage;
     }
     public static Derecmessage.DeRecMessage createGetShareResponseMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id currentSecretId,
             DeRecSecret.Id recoveringSecretId, ResultOuterClass.Result result, Storeshare.CommittedDeRecShare committedDeRecShare) {
         Getshare.GetShareResponseMessage getShareResponseMessage =
                 Getshare.GetShareResponseMessage.newBuilder()
                         .setResult(result)
                         .setCommittedDeRecShare(committedDeRecShare)
                         .build();

         Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, currentSecretId,
                 builder -> builder.setGetShareResponseMessage(getShareResponseMessage)
         );
         return deRecMessage;
     }





//     public static byte[] getPackagedBytes(int publicKeyId,
//                            byte[] serializedDeRecMessage) {
////        byte[] bytes = deRecMessage.toByteArray();
//
//         byte[] signedBytes = signThenEncrypt(serializedDeRecMessage);
//        byte[] withPublicKeyId = ByteBuffer.allocate(4 + signedBytes.length)
//                .putInt(publicKeyId)
//                .put(signedBytes)
//                .array();
//        return withPublicKeyId;
//    }

    public static byte[] getPackagedBytes(int publicKeyId, byte[] serializedDeRecMessage, boolean isSharer,
                                          DeRecSecret.Id secretId, DeRecIdentity receiverId,
                                          boolean shouldSign) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());

        try {
            Derecmessage.DeRecMessage msg = Derecmessage.DeRecMessage.parseFrom(serializedDeRecMessage);
            printDeRecMessage(msg, "Sending ");
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }

        if (LibState.getInstance().useRealCryptoLib) {
            String publicEncryptionKey = "";
            String privateSignatureKey = isSharer ?
                    LibState.getInstance().getMeSharer().getMyLibId().getSignaturePrivateKey() :
                    LibState.getInstance().getMeHelper().getMyLibId().getSignaturePrivateKey();
            String publicSignatureKey = isSharer ?
                    LibState.getInstance().getMeSharer().getMyLibId().getSignaturePublicKey() :
                    LibState.getInstance().getMeHelper().getMyLibId().getSignaturePublicKey();

            // Find the publicEncryptionKey of the receiver.
            // If we are the sharer, find the publicEncryptionKey of the helper.
            // And if we are the helper, find the publicEncryptionKey of the sharer
            if (isSharer) {
////                // TODO: Remove this debug prints
//                staticLogger.debug("I have " + LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().size() + " helpers");
//                for (var hs : LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses()) {
//                    staticLogger.debug("Helper" + hs);
//                    staticLogger.debug("  helper with public encryption key" + hs.getId().getPublicEncryptionKey());
//                    staticLogger.debug("  helper with public signature key" + hs.getId().getPublicSignatureKey());
//                }

                Optional<? extends DeRecHelperStatus> helperStatusOptional =
                        LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream().filter(hs -> hs.getId().equals(receiverId)).findFirst();
                if (helperStatusOptional.isPresent()) {
                    publicEncryptionKey = helperStatusOptional.get().getId().getPublicEncryptionKey();
                } else {
                    staticLogger.debug("Could not find helper status of receiver: " + receiverId.getName());
                    return null;
                }
//                var helperStatus = (DeRecHelperStatus) helperStatusOptional.get();
//                if (helperStatus == null) {
//                    System.out.println("Could not find helper status of receiver: " + receiverId.getName());
//                    return null;
//                }
//                System.out.println("In getPackagedBytes, found helper " + helperStatus.getId().getName());
//                publicEncryptionKey = helperStatus.getId().getPublicEncryptionKey();
            } else {
                Optional<? extends SharerStatusImpl> sharerStatusOptional = LibState.getInstance().getMeHelper().getSharers().stream()
                        .filter(ss -> ss.getId().equals(receiverId)).findFirst();
                if (sharerStatusOptional.isPresent()) {
                    publicEncryptionKey = sharerStatusOptional.get().getId().getPublicEncryptionKey();
                } else {
                    System.out.println("Could not find sharer status of receiver: " + receiverId.getName());
                    return null;
                }

//                SharerStatusImpl sharerStatus = sharerStatusOptional.get();
//                if (sharerStatus == null) {
//                    System.out.println("Could not find sharer status of receiver: " + receiverId.getName());
//                    return null;
//                }
//                System.out.println("In getPackagedBytes, found sharer " + sharerStatus.getId().getName());
//                publicEncryptionKey = sharerStatus.getId().getPublicEncryptionKey();
            }

            staticLogger.debug("About to signThenEncrypt with privateSignatureKey=" + privateSignatureKey + ", " +
                    "publicEncryptionKey=" + publicEncryptionKey);
            byte[] signedBytes = LibState.getInstance().getDerecCryptoImpl().signThenEncrypt(serializedDeRecMessage,
                    Base64.getDecoder().decode(privateSignatureKey),
                    Base64.getDecoder().decode(publicEncryptionKey));

//            if (shouldSign) {
//                staticLogger.debug("About to signThenEncrypt with privateSignatureKey=" + privateSignatureKey + ", " +
//                        "publicEncryptionKey=" + publicEncryptionKey);
//                signedBytes = LibState.getInstance().getDerecCryptoImpl().signThenEncrypt(serializedDeRecMessage,
//                        Base64.getDecoder().decode(privateSignatureKey),
//                        Base64.getDecoder().decode(publicEncryptionKey));
//            } else {
//                staticLogger.debug("About to encrypt only - not signing");
//                signedBytes = LibState.getInstance().getDerecCryptoImpl().encrypt(serializedDeRecMessage,
//                        Base64.getDecoder().decode(publicEncryptionKey));
//            }

            byte[] withPublicKeyId = ByteBuffer.allocate(4 + signedBytes.length)
                    .putInt(publicKeyId)
                    .put(signedBytes)
                    .array();
            return withPublicKeyId;
        } else {
            byte[] signedBytes = signThenEncrypt(serializedDeRecMessage);
            byte[] withPublicKeyId = ByteBuffer.allocate(4 + signedBytes.length)
                    .putInt(publicKeyId)
                    .put(signedBytes)
                    .array();
            return withPublicKeyId;
        }
    }

    public static byte[] parsePackagedBytes(byte[] receivedMessage, boolean verificationNeeded) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());
        ByteBuffer buffer = ByteBuffer.wrap(receivedMessage);
        // Extract the publicKeyId from the first 4 bytes
        int extractedPublicKeyId = buffer.getInt();

        byte[] remainingBytes = new byte[receivedMessage.length - 4];
        System.arraycopy(receivedMessage, 4, remainingBytes, 0, remainingBytes.length);

        DeRecIdentity peerDeRecIdentity = LibState.getInstance().publicKeyIdToIdentityMap.get(extractedPublicKeyId);
        byte[] decryptedAndVerifiedMsg;
        if (verificationNeeded && (peerDeRecIdentity == null)) {
            staticLogger.debug("Dropping Message: No peerDeRecIdentity found for extractedPublicKeyId: " + extractedPublicKeyId);
            LibState.getInstance().printPublicKeyIdToIdentityMap();
            return null;
        } else if (verificationNeeded && (peerDeRecIdentity != null)) {
            staticLogger.debug("About to decryptThenVerify");
            decryptedAndVerifiedMsg = LibState.getInstance().getDerecCryptoImpl().decryptThenVerify(remainingBytes,
                    Base64.getDecoder().decode(peerDeRecIdentity.getPublicSignatureKey())
                    , Base64.getDecoder().decode(LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey()));
        } else {
            staticLogger.debug("About to decrypt only - not verifying");
            decryptedAndVerifiedMsg = LibState.getInstance().getDerecCryptoImpl().decrypt(remainingBytes,
                   Base64.getDecoder().decode(LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey()));
        }

//        if (peerDeRecIdentity == null) {
//            staticLogger.debug("Dropping Message: No peerDeRecIdentity found for extractedPublicKeyId: " + extractedPublicKeyId);
//            LibState.getInstance().printPublicKeyIdToIdentityMap();
//            return null;
//        }
//        if (LibState.getInstance().useRealCryptoLib) {
//            byte[] decryptedAndVerifiedMsg;
//            if (peerDeRecIdentity == null) {
//                decryptedAndVerifiedMsg = LibState.getInstance().getDerecCryptoImpl().decrypt(remainingBytes,
//                        LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey().getBytes(),
//                        LibState.getInstance().myHelperAndSharerId.getEncryptionPublicKey().getBytes());
//            } else {
//                decryptedAndVerifiedMsg = LibState.getInstance().getDerecCryptoImpl().decryptThenVerify(remainingBytes,
//                        peerDeRecIdentity.getPublicSignatureKey().getBytes()
//                        , LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey().getBytes(),
//                        LibState.getInstance().myHelperAndSharerId.getEncryptionPublicKey().getBytes());
//            }


            return decryptedAndVerifiedMsg;

//        } else {
//            // parse these bytes now
//            return remainingBytes;
//        }
    }

    public static boolean parseAndProcessPackagedBytes(byte[] receivedMessage) {
        Logger staticLogger = LoggerFactory.getLogger(MessageFactory.class.getName());
        try {
            ByteBuffer buffer = ByteBuffer.wrap(receivedMessage);
            // Extract the publicKeyId from the first 4 bytes
            int extractedPublicKeyId = buffer.getInt();

            byte[] remainingBytes = new byte[receivedMessage.length - 4];
            System.arraycopy(receivedMessage, 4, remainingBytes, 0, remainingBytes.length);

            DeRecIdentity peerDeRecIdentity = LibState.getInstance().publicKeyIdToIdentityMap.get(extractedPublicKeyId);
            byte[] decryptedAndVerifiedMsg;

            Derecmessage.DeRecMessage derecmessage = null;

            byte[] decryptedMsg = LibState.getInstance().getDerecCryptoImpl().decrypt(remainingBytes,
                    Base64.getDecoder().decode(LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey()));
            int signatureLength = 64;
            byte[] signatureBytes = new byte[signatureLength];
            byte[] msgToParse = new byte[decryptedMsg.length - signatureLength];
            // Copy the first 64 bytes to signatureBytes
            System.arraycopy(decryptedMsg, 0, signatureBytes, 0, signatureLength);
            // Copy the remaining bytes to msgToParse
            System.arraycopy(decryptedMsg, signatureLength, msgToParse, 0, msgToParse.length);
            derecmessage = Derecmessage.DeRecMessage.parseFrom(msgToParse);

            String senderSignaturePublicKey = "";
            // For PairRequest and PairResponse messages, the sender's signature key should be extracted from the received message
            if (derecmessage.hasMessageBodies() && derecmessage.getMessageBodies().hasSharerMessageBodies() &&
                    derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).hasPairRequestMessage()) {
                senderSignaturePublicKey = derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).getPairRequestMessage().getPublicSignatureKey();
            } else if (derecmessage.hasMessageBodies() && derecmessage.getMessageBodies().hasHelperMessageBodies() && derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).hasPairResponseMessage()) {
                senderSignaturePublicKey = derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).getPairResponseMessage().getPublicSignatureKey();
            } else {
                senderSignaturePublicKey = peerDeRecIdentity.getPublicSignatureKey();
            }
            byte[] verificationResult = LibState.getInstance().getDerecCryptoImpl().verify(msgToParse, signatureBytes, Base64.getDecoder().decode(senderSignaturePublicKey));
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

//     void junk() {
//
//        boolean onlyAcceptPairingMessages = true;
//        try {
//            staticLogger.debug("About to decrypt (no verify)");
//            decryptedMsg = LibState.getInstance().getDerecCryptoImpl().decrypt(remainingBytes,
//                    Base64.getDecoder().decode(LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey()));
//            if (decryptedMsg != null) {
//                try {
//                    derecmessage = Derecmessage.DeRecMessage.parseFrom(decryptedMsg);
//                } catch (Exception ex) {
//                    staticLogger.debug("About to decryptThenVerify");
//                    decryptedMsg = LibState.getInstance().getDerecCryptoImpl().decryptThenVerify(remainingBytes,
//                            Base64.getDecoder().decode(peerDeRecIdentity.getPublicSignatureKey())
//                            , Base64.getDecoder().decode(LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey()));
//                    if (decryptedMsg != null) {
//                        try {
//                            derecmessage = Derecmessage.DeRecMessage.parseFrom(decryptedMsg);
//                            onlyAcceptPairingMessages = false;
//                        } catch (Exception ex2) {
//                            staticLogger.debug("Exception in decryptThenVerify", ex2);
//                        }
//                    }
//                }
//            }
//        } catch (Exception ex3) {
//            staticLogger.debug("Exception in decryptThenVerify", ex3);
//        }
//
//        if (!onlyAcceptPairingMessages ||
//                (onlyAcceptPairingMessages &&
//                        ((derecmessage.hasMessageBodies() &&
//                                derecmessage.getMessageBodies().hasSharerMessageBodies() &&
//                                derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).hasPairRequestMessage()) ||
//                                (derecmessage.hasMessageBodies() &&
//                                        derecmessage.getMessageBodies().hasHelperMessageBodies() &&
//                                        derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).hasPairResponseMessage()))
//                )) {
//            MessageParser mp = new MessageParser();
//            mp.parseMessage(extractedPublicKeyId, derecmessage);
//            return true;
//        } else {
//            // Drop the message
//            logger.info("Handle: could not verify the signature on the received message, and it " +
//                    "wasn't a pairing message. Dropping");
//        }
//        return false;
//    }

    public static int extractPublicKeyIdFromPackagedBytes(byte[] receivedMessage) {
        ByteBuffer buffer = ByteBuffer.wrap(receivedMessage);
        // Extract the publicKeyId from the first 4 bytes
        int extractedPublicKeyId = buffer.getInt();
        return extractedPublicKeyId;
    }


//    public static byte[] signThenEncrypt(byte[] serializedDeRecMessage, byte[] signaturePrivateKey,
//                                         byte[] encryptionPublicKey)
     public static byte[] signThenEncrypt(byte[] serializedDeRecMessage) {
         //  public byte[] signThenEncrypt(byte[] message, byte[] signPrivKey, byte[] encPubKey) {
        // TODO implement this
        return serializedDeRecMessage;
    }
    public static byte[] decryptThenVerifySign(int publicKeyId,
                                 byte[] deserializedDeRecMessage) {
        // TODO implement this
        return deserializedDeRecMessage;
    }
}
