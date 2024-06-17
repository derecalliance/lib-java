package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.lib.LibIdentity;
//import org.derecalliance.derec.lib.LibState;
import com.google.protobuf.ByteString;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.protobuf.*;

import java.util.List;
import java.util.Optional;

//import static org.derecalliance.derec.api.GetSecretIdsVersionsMessages.sendGetSecretIdsVersionsRequestMessage;
//import static org.derecalliance.derec.api.MessageFactory.createPairRequestMessage;
//import static org.derecalliance.derec.api.MessageFactory.getPackagedBytes;
//import static org.derecalliance.derec.lib.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.GetSecretIdsVersionsMessages.sendGetSecretIdsVersionsRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.createPairRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

class PairMessages {
     PairMessages() {

    }


     public static Optional<String> extractFromCommunicationInfo(String key,
                                                          Pair.PairRequestMessage message) {
         Optional<String> val =
                 message.getCommunicationInfo().getCommunicationInfoEntriesList().stream()
                         .filter(e -> key.equals(e.getKey()))
                         .map(e -> e.getStringValue())
                         .findFirst();

         return val;
     }
     public static Optional<String> extractFromCommunicationInfo(String key,
                                                          Pair.PairResponseMessage message) {
         Optional<String> val =
                 message.getCommunicationInfo().getCommunicationInfoEntriesList().stream()
                         .filter(e -> key.equals(e.getKey()))
                         .map(e -> e.getStringValue())
                         .findFirst();

         return val;
     }
     public static Optional<DeRecIdentity> createIdentityFromPairRequest(Pair.PairRequestMessage message) {
         Optional<String> name = extractFromCommunicationInfo("name", message);
         Optional<String> address = extractFromCommunicationInfo("address",
                 message);
         Optional<String> contact = extractFromCommunicationInfo("contact",
                 message);

         var sharerIdentity =  Optional.of(new DeRecIdentity(name.get(),
                 contact.get(), address.get(),
                 message.getPublicEncryptionKey(), message.getPublicSignatureKey()));
         sharerIdentity.ifPresent(id ->  LibState.getInstance().messageHashToIdentityMap.put(ByteString.copyFrom(id.getPublicEncryptionKeyDigest()),
                 id));
         return sharerIdentity;

     }

     static void handlePairRequest(int publicKeyId, DeRecIdentity nullSenderId, DeRecIdentity receiverId, byte[] secretId,
                                   Pair.PairRequestMessage message) {
         try {
             // Process PairRequestMessage
             System.out.println("In handlePairRequest -  sharer's kind is " + message.getSenderKind());
             if (message.getSenderKind() == Pair.SenderKind.SHARER_RECOVERY) {
                 System.out.println("******** Sharer is in reocvery!");
             }


             // Debug - prints contents of the received PairRequest message

             System.out.println("Nonce: " + message.getNonce());
             List<Communicationinfo.CommunicationInfoKeyValue> lst =
                     message.getCommunicationInfo().getCommunicationInfoEntriesList();
             for (int i = 0; i < lst.size(); i++) {
                 Communicationinfo.CommunicationInfoKeyValue entry = lst.get(i);
                 System.out.println("key: " + entry.getKey() + ", Val: " + entry.getStringValue());
             }

             // Validation checks
             boolean validNonce =
                     LibState.getInstance().getMeHelper().validateAndRemoveNonce(message.getNonce());
             if (!validNonce) {
                 System.out.println("Invalid nonce " + message.getNonce() + " " +
                         "received");
                 return;
             }


             boolean validParameterRange =
                     LibState.getInstance().getMeHelper().validateParameterRange(message.getParameterRange());
             if (!validParameterRange) {
                 System.out.println("Invalid parameter range received");
                 return;
             }

             Optional<String> addressValue = extractFromCommunicationInfo("address",
                     message);
             if (!addressValue.isPresent()) {
                 System.out.println("Could not find address in the PairRequest " +
                         "message");
                 return;
             }
             String toUri = addressValue.get();

             ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                     .setStatus(ResultOuterClass.StatusEnum.OK)
                     .setMemo("Thank you for pairing with me!")
                     .build();

             Communicationinfo.CommunicationInfo communicationInfo =
                     buildCommunicationInfo(LibState.getInstance().getMeHelper().getMyLibId());

             Optional<DeRecIdentity> sharerId = createIdentityFromPairRequest(message);
             if (sharerId.isEmpty()) {
                 return;
             }
             LibState.getInstance().registerPublicKeyId(publicKeyId, sharerId.get());
             LibState.getInstance().printPublicKeyIdToIdentityMap();
             SharerStatusImpl sharerStatus = new SharerStatusImpl(sharerId.get());
             sharerStatus.setRecovering(message.getSenderKind() == Pair.SenderKind.SHARER_RECOVERY);
             LibState.getInstance().getMeHelper().addSharer(sharerStatus, new DeRecSecret.Id(secretId));
             System.out.println("added sharer");
             LibState.getInstance().getMeHelper().addSecret(sharerStatus, new DeRecSecret.Id(secretId));
             System.out.println("added secret");

             // Send PairResponse
             System.out.println("About to send pair response with public signature key: " + LibState.getInstance().getMeHelper().getMyLibId().getSignaturePublicKey());
             sendPairResponseMessage(receiverId, sharerStatus.getId(),
                     new DeRecSecret.Id(secretId), toUri,
                     LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(), result, Pair.SenderKind.HELPER,
                     LibState.getInstance().getMeHelper().getMyLibId().getSignaturePublicKey(),
                     communicationInfo, message.getNonce(),
                     LibState.getInstance().getMeHelper().getParameterRange());

             DeRecHelper.NotificationResponse response =
                     LibState.getInstance().getMeHelper().deliverNotification(DeRecHelper.Notification.StandardHelperNotificationType.PAIR_INDICATION,
                             sharerId.get(), new DeRecSecret.Id(secretId), -1);
         } catch (Exception ex) {
             System.out.println("Exception in handlePairRequest");
             ex.printStackTrace();
         }
     }
     static void handlePairResponse(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, byte[] secretId,
                                    Pair.PairResponseMessage message) {
         try {
             System.out.println("In handlePairResponse from " + senderId.getName());
             var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(new DeRecSecret.Id(secretId));
             System.out.println("In handlePairResponse - Secret is: " + secret);
             if (secret != null) {
                 Optional<HelperStatusImpl> match = (Optional<HelperStatusImpl>) secret.getHelperStatuses().stream()
                         .filter(hs -> hs.getId().getPublicEncryptionKey().equals(senderId.getPublicEncryptionKey()))
                         .findFirst();
                 HelperStatusImpl helperStatus = match.get();
                 LibState.getInstance().registerPublicKeyId(publicKeyId, helperStatus.getId());
                 LibState.getInstance().printPublicKeyIdToIdentityMap();
                 System.out.println("Got signature key: " + message.getPublicSignatureKey() + " for " + helperStatus.getId().getName());
                 helperStatus.getId().setPublicSignatureKey(message.getPublicSignatureKey());
                 System.out.println("Setting pairing status to Paired for " + helperStatus.getId().getName());
                 helperStatus.setStatus(DeRecPairingStatus.PairingStatus.PAIRED);
                 LibState.getInstance().getMeSharer().deliverNotification(
                 DeRecStatusNotification.StandardNotificationType.HELPER_PAIRED,
                         DeRecStatusNotification.NotificationSeverity.NORMAL, "Helper paired", secret, null,
                         helperStatus);

                 secret.helperStatusChanged();
             }

             if (secret.isRecovering()) {
                 System.out.println("In handlePairResponse, I am recovering");
                 sendGetSecretIdsVersionsRequestMessage(
                         receiverId, senderId, new DeRecSecret.Id(secretId),
                         LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId());
             }
         } catch (Exception ex) {
             System.out.println("Exception in handlePairResponse");
             ex.printStackTrace();
         }
     }

    public static Communicationinfo.CommunicationInfo buildCommunicationInfo(LibIdentity libId) {
        Communicationinfo.CommunicationInfoKeyValue nameKeyValue = Communicationinfo.CommunicationInfoKeyValue.newBuilder()
                .setKey("name")
                .setStringValue(libId.getMyId().getName())
                .build();
        Communicationinfo.CommunicationInfoKeyValue addressKeyValue =
                Communicationinfo.CommunicationInfoKeyValue.newBuilder()
                        .setKey("address")
                        .setStringValue(libId.getMyId().getAddress())
                        .build();
        Communicationinfo.CommunicationInfoKeyValue contactKeyValue =
                Communicationinfo.CommunicationInfoKeyValue.newBuilder()
                        .setKey("contact")
                        .setStringValue(libId.getMyId().getContact())
                        .build();
        Communicationinfo.CommunicationInfo communicationInfo = Communicationinfo.CommunicationInfo.newBuilder()
                .addCommunicationInfoEntries(nameKeyValue)
                .addCommunicationInfoEntries(addressKeyValue)
                .addCommunicationInfoEntries(contactKeyValue)
                .build();
        return communicationInfo;
    }

    public static void sendPairRequestMessage(DeRecIdentity senderId, DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                              String toUri, Pair.SenderKind senderKind, String publicSignatureKey, String publicEncryptionKey,
                                              int publicKeyId, Communicationinfo.CommunicationInfo communicationInfo,
                                              long nonce, Parameterrange.ParameterRange parameterRange ) {
        Derecmessage.DeRecMessage deRecMessage = createPairRequestMessage(senderId, receiverId, secretId, senderKind,
                publicSignatureKey, publicEncryptionKey, publicKeyId,
                communicationInfo, nonce, parameterRange);

//        System.out.print("------ created protobuf  bytes: ");
//        for (int i = 0; i < 20; i++) {
//            System.out.print(deRecMessage.toByteArray()[i] + ", ");
//        }
//        System.out.println("");




        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), true, secretId, receiverId);

//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());


//        System.out.print("------ sending wire bytes: ");
//        for (int i = 0; i < 20; i++) {
//            System.out.print(msgBytes[i] + ", ");
//        }
//        System.out.println("");

        sendHttpRequest(toUri, msgBytes);
    }

    public static void sendPairResponseMessage(DeRecIdentity senderId,
                                        DeRecIdentity receiverId, DeRecSecret.Id secretId,
                                        String toUri,
                                        int publicKeyId, // Not in the
                                        // message, but is needed to for
                                        // prepending in the message
                                        ResultOuterClass.Result result,
                                        Pair.SenderKind senderKind,
                                       String publicSignatureKey,
                                       Communicationinfo.CommunicationInfo communicationInfo,
                                       long nonce, Parameterrange.ParameterRange parameterRange ) {
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createPairResponseMessage(senderId, receiverId,
                secretId,
                result, senderKind, publicSignatureKey,
                communicationInfo, nonce, parameterRange);

        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray(), false, secretId, receiverId);
//        byte[] msgBytes = getPackagedBytes(publicKeyId, deRecMessage.toByteArray());
        sendHttpRequest(toUri, msgBytes);
    }
}