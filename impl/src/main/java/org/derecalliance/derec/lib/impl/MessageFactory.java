package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.api.DeRecMessage;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
//import org.derecalliance.derec.lib.Share;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

 class MessageFactory {
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
    public static Derecmessage.DeRecMessage createStoreShareRequestMessage(DeRecIdentity senderId,
                                                                         DeRecIdentity receiverId,
                                                                           DeRecSecret.Id secretId, ShareImpl share) {
        SecretImpl secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);
        List<Integer> keepList = secret.versionsMap.keySet().stream().toList();

        Storeshare.StoreShareRequestMessage storeShareRequestMessage =  Storeshare.StoreShareRequestMessage.newBuilder()
                .setShare(ByteString.copyFrom(share.getCommittedDeRecShareBytes()))
                .setShareAlgorithm(1)
                .setVersion(share.getVersionNumber())
                .addAllKeepList(keepList)
                .build();

        Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                senderId, receiverId, secretId,
                builder -> builder.setStoreShareRequestMessage(storeShareRequestMessage)
        );
        MessageParser.printDeRecMessage(deRecMessage, "Sending messsage ");
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
             DeRecIdentity senderId, DeRecIdentity receiverId,DeRecSecret.Id secretId,
             int versionNumber) {
         Getshare.GetShareRequestMessage getShareRequestMessage =  Getshare.GetShareRequestMessage.newBuilder()
                 .setSecretId(ByteString.copyFrom(secretId.getBytes()))
                 .setShareVersion(versionNumber)
                 .build();

         Derecmessage.DeRecMessage deRecMessage = createSharerMessage(
                 senderId, receiverId, secretId,
                 builder -> builder.setGetShareRequestMessage(getShareRequestMessage)
         );
         return deRecMessage;
     }
     public static Derecmessage.DeRecMessage createGetShareResponseMessage(
             DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
             ResultOuterClass.Result result, Storeshare.CommittedDeRecShare committedDeRecShare) {
         Getshare.GetShareResponseMessage getShareResponseMessage =
                 Getshare.GetShareResponseMessage.newBuilder()
                         .setResult(result)
                         .setCommittedDeRecShare(committedDeRecShare)
                         .build();

         Derecmessage.DeRecMessage deRecMessage = createHelperMessage(senderId, receiverId, secretId,
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
                                          DeRecSecret.Id secretId, DeRecIdentity receiverId) {
        final boolean useRealCryptoLib = false;
        if (useRealCryptoLib) {
//            String publicEncryptionKey = "";
//                    //      public byte[] signThenEncrypt(byte[] message, byte[] signPrivKey, byte[] encPubKey) {
//            String privateSignatureKey = isSharer ?
//                    LibState.getInstance().getMeSharer().getMyLibId().getSignaturePrivateKey() :
//                    LibState.getInstance().getMeHelper().getMyLibId().getSignaturePrivateKey();
//            if (isSharer) {
//                Optional<? extends DeRecHelperStatus> helperStatusOptional =
//                        LibState.getInstance().getMeSharer().getSecret(secretId).getHelperStatuses().stream().filter(hs -> hs.getId().equals(receiverId)).findFirst();
//                var helperStatus = (DeRecHelperStatus) helperStatusOptional.get();
//                if (helperStatus == null) {
//                    System.out.println("Could not find helper status of receiver: " + receiverId.getName());
//                    return null;
//                }
//                System.out.println("In getPackagedBytes, found helper " + helperStatus.getId().getName());
//                publicEncryptionKey = helperStatus.getId().getPublicEncryptionKey();
//            } else {
//                Optional<? extends SharerStatusImpl> sharerStatusOptional = LibState.getInstance().getMeHelper().getSharers().stream()
//                        .filter(ss -> ss.getId().equals(receiverId)).findFirst();
//                var sharerStatus = (DeRecHelperStatus) sharerStatusOptional.get();
//                if (sharerStatus == null) {
//                    System.out.println("Could not find sharer status of receiver: " + receiverId.getName());
//                    return null;
//                }
//                System.out.println("In getPackagedBytes, found sharer " + sharerStatus.getId().getName());
//                publicEncryptionKey = sharerStatus.getId().getPublicEncryptionKey();
//            }
//
//            byte[] signedBytes = signThenEncrypt(serializedDeRecMessage, privateSignatureKey,
//                    publicEncryptionKey); // TODO: uncomment this (useCryptoLib)
//
//            byte[] withPublicKeyId = ByteBuffer.allocate(4 + signedBytes.length)
//                    .putInt(publicKeyId)
//                    .put(signedBytes)
//                    .array();
//            return withPublicKeyId;
            return ("hello").getBytes(); // TODO: comment this (useCryptoLib)
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
        ByteBuffer buffer = ByteBuffer.wrap(receivedMessage);
        // Extract the publicKeyId from the first 4 bytes
        int extractedPublicKeyId = buffer.getInt();

        byte[] remainingBytes = new byte[receivedMessage.length - 4];
        System.arraycopy(receivedMessage, 4, remainingBytes, 0, remainingBytes.length);

        if (! verificationNeeded) {
            final boolean useRealCryptoLib = false;
            if (useRealCryptoLib) {
                // TODO: call decrypt here
                // decrypt()
            } else {
                return remainingBytes;
            }
        }

        DeRecIdentity peerDeRecIdentity = LibState.getInstance().publicKeyIdToIdentityMap.get(extractedPublicKeyId);
        if (peerDeRecIdentity == null) {
            System.out.println("Dropping Message: No peerDeRecIdentity found for extractedPublicKeyId: " + extractedPublicKeyId);
            LibState.getInstance().printPublicKeyIdToIdentityMap();
            return null;
        }
        final boolean useRealCryptoLib = false;
        if (useRealCryptoLib) {
//                 byte[] decryptedAndVerifiedMsg =  decryptThenVerify(remainingBytes,
//                    peerDeRecIdentity.getPublicSignatureKey().getBytes()
//                    , LibState.getInstance().myHelperAndSharerId.getEncryptionPrivateKey()) // TODO: uncomment this (useCryptoLib)
//            return decryptedAndVerifiedMsg;
            return null;
        } else {
            // parse these bytes now
            return remainingBytes;
        }
    }

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
