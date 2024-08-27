/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.derecalliance.derec.lib.impl;

import static org.derecalliance.derec.lib.impl.GetSecretIdsVersionsMessages.sendGetSecretIdsVersionsRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.createPairRequestMessage;
import static org.derecalliance.derec.lib.impl.MessageFactory.getPackagedBytes;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;

import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Optional;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PairMessages {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    /**
     * Extract a specific value from the CommunicationInfo entry in the PairRequestMessage protobuf
     *
     * @param key     The key value to be extracted
     * @param message PairRequestMessage
     * @return CommunicationInfo entry value associated with the given key
     */
    public static Optional<String> extractFromCommunicationInfo(String key, Pair.PairRequestMessage message) {
        Optional<String> val = message.getCommunicationInfo().getCommunicationInfoEntriesList().stream()
                .filter(e -> key.equals(e.getKey()))
                .map(e -> e.getStringValue())
                .findFirst();

        return val;
    }

    /**
     * Create a DeRecIdentity from the information in the PairRequestMessage
     *
     * @param secretId SecretId that pairing was done for
     * @param message  PairRequestMessage
     * @return DeRecIdentity that was created
     */
    public static Optional<DeRecIdentity> createIdentityFromPairRequest(
            DeRecSecret.Id secretId, Pair.PairRequestMessage message) {
        Optional<String> name = extractFromCommunicationInfo("name", message);
        Optional<String> address = extractFromCommunicationInfo("address", message);
        Optional<String> contact = extractFromCommunicationInfo("contact", message);

        var sharerIdentity = Optional.of(new DeRecIdentity(
                name.get(),
                contact.get(),
                address.get(),
                message.getPublicKeyId(),
                message.getPublicEncryptionKey(),
                message.getPublicSignatureKey()));

        sharerIdentity.ifPresent(id -> LibState.getInstance()
                .registerMessageHashAndSecretIdToIdentity(
                        ByteString.copyFrom(id.getPublicEncryptionKeyDigest()), secretId, id));
        return sharerIdentity;
    }

    /**
     * Handles the received PairRequestMessage.
     *
     * @param publicKeyId  The public key id of the message receiver
     * @param nullSenderId DeRecIdentity of the message sender (null because the user does not know the sender yet)
     * @param receiverId   DeRecIdentity of the message receiver
     * @param secretId     SecretId of the secret this message was sent in the context of
     * @param message      The PairRequestMessage
     */
    static void handlePairRequest(
            int publicKeyId,
            DeRecIdentity
                    nullSenderId, // senderId is null because the message receiver has not yet created a DeRecIdentity
            // for the message sender
            DeRecIdentity receiverId,
            byte[] secretId,
            Pair.PairRequestMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(PairMessages.class.getName());
        try {
            // Process PairRequestMessage
            staticLogger.debug("In handlePairRequest -  sharer's kind is " + message.getSenderKind());
            if (message.getSenderKind() == Pair.SenderKind.SHARER_RECOVERY) {
                staticLogger.debug("******** Sharer is in reocvery!");
            }

            // Debug - prints contents of the received PairRequest message
            staticLogger.debug("Nonce: " + message.getNonce());
            List<Communicationinfo.CommunicationInfoKeyValue> lst =
                    message.getCommunicationInfo().getCommunicationInfoEntriesList();
            for (int i = 0; i < lst.size(); i++) {
                Communicationinfo.CommunicationInfoKeyValue entry = lst.get(i);
                staticLogger.debug("key: " + entry.getKey() + ", Val: " + entry.getStringValue());
            }

            // Validation checks for nonce, parameter range, and address
            boolean validNonce = LibState.getInstance().getMeHelper().validateAndRemoveNonce(message.getNonce());
            if (!validNonce) {
                staticLogger.debug("Invalid nonce " + message.getNonce() + " " + "received");
                return;
            }

            boolean validParameterRange =
                    LibState.getInstance().getMeHelper().validateParameterRange(message.getParameterRange());
            if (!validParameterRange) {
                staticLogger.debug("Invalid parameter range received");
                return;
            }

            Optional<String> addressValue = extractFromCommunicationInfo("address", message);
            if (!addressValue.isPresent()) {
                staticLogger.debug("Could not find address in the PairRequest " + "message");
                return;
            }
            String toUri = addressValue.get();

            ResultOuterClass.Result result = ResultOuterClass.Result.newBuilder()
                    .setStatus(ResultOuterClass.StatusEnum.OK)
                    .setMemo("Thank you for pairing with me!")
                    .build();

            Communicationinfo.CommunicationInfo communicationInfo =
                    buildCommunicationInfo(LibState.getInstance().getMeHelper().getMyLibId());

            // Create a DeRecIdentity for the sharer
            Optional<DeRecIdentity> sharerId = createIdentityFromPairRequest(new DeRecSecret.Id(secretId), message);
            if (sharerId.isEmpty()) {
                return;
            }
            staticLogger.debug("Created DeRecIdentity: " + sharerId.get());

            LibState.getInstance().printPublicKeyIdToIdentityMap();
            SharerStatusImpl sharerStatus = new SharerStatusImpl(sharerId.get());
            sharerStatus.setRecovering(message.getSenderKind() == Pair.SenderKind.SHARER_RECOVERY);
            LibState.getInstance().getMeHelper().addSharer(sharerStatus, new DeRecSecret.Id(secretId));
            staticLogger.debug("added sharer");
            LibState.getInstance().getMeHelper().addSecret(sharerStatus, new DeRecSecret.Id(secretId));
            staticLogger.debug("added secret");

            // If the sharer is in recovery mode, wait for the UI response from the helper to reconcile the sharer's
            // old identities with their recovering identity
            if (message.getSenderKind() == Pair.SenderKind.SHARER_RECOVERY) {
                var uiResponse = (HelperImpl.NotificationResponse) LibState.getInstance()
                        .getMeHelper()
                        .deliverNotification(
                                DeRecHelper.Notification.StandardHelperNotificationType.PAIR_INDICATION_RECOVERY,
                                sharerId.get(),
                                new DeRecSecret.Id(secretId),
                                -1);
                staticLogger.debug("Got uiResponse after sending PAIR_INDICATION_RECOVERY notif: "
                        + uiResponse.getReferenceObject());
                if (uiResponse.getReferenceObject() == null) {
                    staticLogger.error("Error: got no reference object");
                    return; // TODO: Handle this better - maybe send a pairing response with an appropriate error code
                }
                LibState.getInstance()
                        .getMeHelper()
                        .registerIdentityReconciliation(
                                sharerId.get().getPublicEncryptionKey(),
                                (List<SharerStatusImpl>) uiResponse.getReferenceObject());
                LibState.getInstance().getMeHelper().printPublicKeyToLostSharerMap();
            }

            // Send PairResponse
            staticLogger.debug("About to send pair response with public signature key: "
                    + LibState.getInstance().getMeHelper().getMyLibId().getSignaturePublicKey());
            sendPairResponseMessage(
                    receiverId,
                    sharerStatus.getId(),
                    new DeRecSecret.Id(secretId),
                    toUri,
                    LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(),
                    result,
                    Pair.SenderKind.HELPER,
                    LibState.getInstance().getMeHelper().getMyLibId().getSignaturePublicKey(),
                    communicationInfo,
                    message.getNonce(),
                    LibState.getInstance().getMeHelper().getParameterRange());

            DeRecHelper.NotificationResponse response = LibState.getInstance()
                    .getMeHelper()
                    .deliverNotification(
                            DeRecHelper.Notification.StandardHelperNotificationType.PAIR_INDICATION,
                            sharerId.get(),
                            new DeRecSecret.Id(secretId),
                            -1);
        } catch (Exception ex) {
            staticLogger.error("Exception in handlePairRequest", ex);
        }
    }

    /**
     * Handles the received PairResponseMessage.
     *
     * @param publicKeyId The public key id of the message receiver
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    SecretId of the secret this message was sent in the context of
     * @param message     The PairResponseMessage
     */
    static void handlePairResponse(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            byte[] secretId,
            Pair.PairResponseMessage message) {
        Logger staticLogger = LoggerFactory.getLogger(PairMessages.class.getName());
        try {
            staticLogger.debug("In handlePairResponse from " + senderId.getName());
            var secret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(new DeRecSecret.Id(secretId));
            staticLogger.debug("In handlePairResponse - Secret is: " + secret);
            if (secret != null) {
                Optional<HelperStatusImpl> match = (Optional<HelperStatusImpl>) secret.getHelperStatuses().stream()
                        .filter(hs -> hs.getId().getPublicEncryptionKey().equals(senderId.getPublicEncryptionKey()))
                        .findFirst();
                HelperStatusImpl helperStatus = match.get();
                LibState.getInstance().printPublicKeyIdToIdentityMap();
                staticLogger.debug("Got signature key: " + message.getPublicSignatureKey() + " for "
                        + helperStatus.getId().getName());
                // Update the signature key of the Helper using the signature key found in the message
                helperStatus.getId().setPublicSignatureKey(message.getPublicSignatureKey());
                staticLogger.debug("Setting pairing status to Paired for "
                        + helperStatus.getId().getName());
                // Update the pairing status of the Helper to Paired
                helperStatus.setStatus(DeRecPairingStatus.PairingStatus.PAIRED);
                // Deliver a notification to the application
                LibState.getInstance()
                        .getMeSharer()
                        .deliverNotification(
                                DeRecStatusNotification.StandardNotificationType.HELPER_PAIRED,
                                DeRecStatusNotification.NotificationSeverity.NORMAL,
                                "Helper paired",
                                secret,
                                null,
                                helperStatus);

                // Create shares and update keepList if necessary
                secret.helperStatusChanged();
            }

            // If the Sharer is recovering a secret, send a GetSecretIdsVersionsRequestMessage to that Helper who sent
            // the PairResponseMessage
            if (secret.isRecovering()) {
                staticLogger.debug("In handlePairResponse, I am recovering");
                sendGetSecretIdsVersionsRequestMessage(
                        receiverId,
                        senderId,
                        new DeRecSecret.Id(secretId),
                        LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId());
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in handlePairResponse", ex);
        }
    }

    /**
     * Populates the protobuf CommunicationInfo based on user's data
     *
     * @param libId Lib identity of the user
     * @return CommunicationInfo protobuf
     */
    public static Communicationinfo.CommunicationInfo buildCommunicationInfo(LibIdentity libId) {
        Communicationinfo.CommunicationInfoKeyValue nameKeyValue =
                Communicationinfo.CommunicationInfoKeyValue.newBuilder()
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

    /**
     * Sends a PairRequestMessage
     *
     * @param senderId            DeRecIdentity of the message sender
     * @param receiverId          DeRecIdentity of the message receiver
     * @param secretId            SecretId of the secret this message is being sent in the context of
     * @param toUri               URI address to send the message to
     * @param senderKind          Sharer in normal or recovery mode
     * @param publicSignatureKey  Public signature key of the message sender
     * @param publicEncryptionKey Public encryption key of the message sender
     * @param publicKeyId         publicKeyId of the message sender
     * @param communicationInfo   communicationInfo of the message sender
     * @param nonce               Nonce to identify pairing session
     * @param parameterRange      parameterRange of the message sender
     */
    public static void sendPairRequestMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            String toUri,
            Pair.SenderKind senderKind,
            String publicSignatureKey,
            String publicEncryptionKey,
            int publicKeyId,
            Communicationinfo.CommunicationInfo communicationInfo,
            long nonce,
            Parameterrange.ParameterRange parameterRange) {
        Derecmessage.DeRecMessage deRecMessage = createPairRequestMessage(
                senderId,
                receiverId,
                secretId,
                senderKind,
                publicSignatureKey,
                publicEncryptionKey,
                publicKeyId,
                communicationInfo,
                nonce,
                parameterRange);

        byte[] msgBytes = getPackagedBytes(
                receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), true, secretId, receiverId, false);
        sendHttpRequest(toUri, msgBytes);
    }

    /**
     * @param senderId           DeRecIdentity of the message sender
     * @param receiverId         DeRecIdentity of the message receiver
     * @param secretId           SecretId of the secret this message is being sent in the context of
     * @param toUri              URI address to send the message to
     * @param publicKeyId        publicKeyId of the message receiver
     * @param result             Handling status of the message
     * @param senderKind         Helper
     * @param publicSignatureKey Public signature key of the message receiver
     * @param communicationInfo  communicationInfo of the message sender
     * @param nonce              Nonce to identify pairing session
     * @param parameterRange     parameterRange of the message sender
     */
    public static void sendPairResponseMessage(
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            DeRecSecret.Id secretId,
            String toUri,
            int publicKeyId,
            ResultOuterClass.Result result,
            Pair.SenderKind senderKind,
            String publicSignatureKey,
            Communicationinfo.CommunicationInfo communicationInfo,
            long nonce,
            Parameterrange.ParameterRange parameterRange) {
        Derecmessage.DeRecMessage deRecMessage = MessageFactory.createPairResponseMessage(
                senderId,
                receiverId,
                secretId,
                result,
                senderKind,
                publicSignatureKey,
                communicationInfo,
                nonce,
                parameterRange);

        byte[] msgBytes = getPackagedBytes(
                receiverId.getPublicEncryptionKeyId(), deRecMessage.toByteArray(), false, secretId, receiverId, false);
        sendHttpRequest(toUri, msgBytes);
    }
}
