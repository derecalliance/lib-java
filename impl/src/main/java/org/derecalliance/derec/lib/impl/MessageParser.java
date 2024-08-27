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

import static org.derecalliance.derec.lib.impl.GetSecretIdsVersionsMessages.handleGetSecretIdsVersionsRequest;
import static org.derecalliance.derec.lib.impl.GetSecretIdsVersionsMessages.handleGetSecretIdsVersionsResponse;
import static org.derecalliance.derec.lib.impl.GetShareMessages.handleGetShareRequest;
import static org.derecalliance.derec.lib.impl.GetShareMessages.handleGetShareResponse;
import static org.derecalliance.derec.lib.impl.PairMessages.handlePairRequest;
import static org.derecalliance.derec.lib.impl.PairMessages.handlePairResponse;
import static org.derecalliance.derec.lib.impl.StoreShareMessages.handleStoreShareRequest;
import static org.derecalliance.derec.lib.impl.StoreShareMessages.handleStoreShareResponse;
import static org.derecalliance.derec.lib.impl.UnpairMessages.handleUnpairRequest;
import static org.derecalliance.derec.lib.impl.UnpairMessages.handleUnpairResponse;
import static org.derecalliance.derec.lib.impl.VerifyShareMessages.handleVerifyShareRequest;
import static org.derecalliance.derec.lib.impl.VerifyShareMessages.handleVerifyShareResponse;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.Base64;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MessageParser {
    static Logger logger = LoggerFactory.getLogger(MessageParser.class.getName());

    /**
     * Print routine for a received message
     *
     * @param message     Received DeRecMessage
     * @param description Additional information to print
     */
    public static void printDeRecMessage(Derecmessage.DeRecMessage message, String description) {
        String senderDigest =
                Base64.getEncoder().encodeToString(message.getSender().toByteArray());
        String receiverDigest =
                Base64.getEncoder().encodeToString(message.getReceiver().toByteArray());
        String secret = Base64.getEncoder().encodeToString(message.getSecretId().toByteArray());

        // Find the message sender and receiver by querying LibState's messageHashAndSecretIdToIdentityMap
        DeRecIdentity senderId = LibState.getInstance()
                .queryMessageHashAndSecretIdToIdentity(
                        message.getSender(),
                        new DeRecSecret.Id(message.getSecretId().toByteArray()));
        DeRecIdentity receiverId = LibState.getInstance()
                .queryMessageHashAndSecretIdToIdentity(
                        message.getReceiver(),
                        new DeRecSecret.Id(message.getSecretId().toByteArray()));

        LibState.getInstance().printMessageHashToIdentityMap();

        if (senderId == null) {
            logger.error("printDeRecMessage: Could not find an entry in hashToIdentityMap for sender "
                    + Base64.getEncoder().encodeToString(senderDigest.getBytes()));
        }
        if (receiverId == null) {
            logger.error("printDeRecMessage: Could not find an entry in hashToIdentityMap for receiver "
                    + Base64.getEncoder().encodeToString(receiverDigest.getBytes()));
        }
        logger.info(
                description + ",Sender: " + senderDigest + " (" + (senderId == null ? "unknown" : senderId.getName())
                        + "), Receiver: " + receiverDigest + " ("
                        + (receiverId == null ? "unknown" : receiverId.getName() + "), Secret: " + secret));

        // Log Sharer and Helper message details
        if (message.hasMessageBodies()) {
            if (message.getMessageBodies().hasSharerMessageBodies()) {
                for (Derecmessage.DeRecMessage.SharerMessageBody body :
                        message.getMessageBodies().getSharerMessageBodies().getSharerMessageBodyList()) {
                    if (body.hasPairRequestMessage()) {
                        logger.info("PairRequestMessage");
                        Pair.PairRequestMessage pairMsg = body.getPairRequestMessage();
                        String encryptionKey = pairMsg.getPublicEncryptionKey();
                        logger.info(" - encryptionKey: " + encryptionKey);

                    } else if (body.hasGetShareRequestMessage()) {
                        logger.info("GetShareRequestMessage for secretId: "
                                + Base64.getEncoder()
                                        .encodeToString(body.getGetShareRequestMessage()
                                                .getSecretId()
                                                .toByteArray())
                                + ", " + "version number: "
                                + body.getGetShareRequestMessage().getShareVersion());
                    } else if (body.hasGetSecretIdsVersionsRequestMessage()) {
                        logger.info("GetSecretIdsVersionsRequestMessage");
                    } else if (body.hasStoreShareRequestMessage()) {
                        logger.info("StoreShareRequestMessage");
                        Storeshare.StoreShareRequestMessage msg = body.getStoreShareRequestMessage();
                        logger.info(" - VersionImpl: " + msg.getVersion() + ", ShareImpl size: "
                                + msg.getShare().size() + ", KeepList: " + msg.getKeepListList());
                    } else if (body.hasUnpairRequestMessage()) {
                        logger.info("UnpairRequestMessage");
                    } else if (body.hasVerifyShareRequestMessage()) {
                        logger.info("VerifyShareRequestMessage");
                        Verify.VerifyShareRequestMessage msg = body.getVerifyShareRequestMessage();
                        logger.info(" - VersionImpl: " + msg.getVersion());
                    } else {
                        logger.info("UNKNOWN sharer message type");
                    }
                }
            } else if (message.getMessageBodies().hasHelperMessageBodies()) {
                for (Derecmessage.DeRecMessage.HelperMessageBody body :
                        message.getMessageBodies().getHelperMessageBodies().getHelperMessageBodyList()) {
                    if (body.hasPairResponseMessage()) {
                        logger.info("PairResponseMessage");
                    } else if (body.hasGetSecretIdsVersionsResponseMessage()) {
                        logger.info("GetSecretIdsVersionsResponseMessage");
                        logger.info(" - ****** SECRETLIST ******");
                        for (Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList list :
                                body.getGetSecretIdsVersionsResponseMessage().getSecretListList()) {
                            logger.info(" - - Secret ID "
                                    + Base64.getEncoder()
                                            .encodeToString(list.getSecretId().toByteArray()));
                            for (int versionNumber : list.getVersionsList()) {
                                logger.info(" - - - version #: " + versionNumber);
                            }
                        }
                    } else if (body.hasErrorResponseMessage()) {
                        logger.info("ErrorResponseMessage");
                    } else if (body.hasGetShareResponseMessage()) {
                        logger.info("GetShareResponseMessage, Result: "
                                + body.getGetShareResponseMessage()
                                        .getResult()
                                        .getStatus()
                                        .toString());
                        try {
                            Storeshare.DeRecShare shareMsg =
                                    Storeshare.DeRecShare.parseFrom(body.getGetShareResponseMessage()
                                            .getCommittedDeRecShare()
                                            .getDeRecShare());
                            logger.info("Version: " + shareMsg.getVersion());
                        } catch (InvalidProtocolBufferException ex) {
                            logger.error("Exception in trying to parse the incoming share as a derec share", ex);
                        }
                    } else if (body.hasUnpairResponseMessage()) {
                        logger.info("UnpairResponseMessage");
                    } else if (body.hasStoreShareResponseMessage()) {
                        logger.info("StoreShareResponseMessage");
                        Storeshare.StoreShareResponseMessage msg = body.getStoreShareResponseMessage();
                        logger.info("Result: " + msg.getResult().getStatus().toString() + ", memo: "
                                + msg.getResult().getMemo());
                    } else if (body.hasVerifyShareResponseMessage()) {
                        logger.info("VerifyShareResponseMessage");
                        Verify.VerifyShareResponseMessage msg = body.getVerifyShareResponseMessage();
                        logger.info("VersionImpl: " + msg.getVersion() + "Result: "
                                + msg.getResult().getStatus().toString() + ", memo: "
                                + msg.getResult().getMemo());
                    } else {
                        logger.info("UNKNOWN helper message type");
                    }
                }
            }
        }
    }

    /**
     * Parses the received DeRecMessage
     *
     * @param publicKeyId publicKeyId of the message receiver
     * @param message     Received message
     */
    void parseMessage(int publicKeyId, Derecmessage.DeRecMessage message) {
        printDeRecMessage(message, "Received ");
        // Handles pause functionality for demo application
        if (LibState.getInstance().getMeHelper().isPaused()) {
            logger.debug("Ignoring message because I'm paused");
            return;
        }

        byte[] secretId = message.getSecretId().toByteArray();
        ByteString senderHash = message.getSender();
        DeRecIdentity senderId =
                LibState.getInstance().queryMessageHashAndSecretIdToIdentity(senderHash, new DeRecSecret.Id(secretId));
        if (senderId == null) {
            logger.debug("Could not find an entry in hashToIdentityMap for sender "
                    + Base64.getEncoder().encodeToString(senderHash.toByteArray()));
            LibState.getInstance().printMessageHashToIdentityMap();

            boolean isPairRequestMessage = message.hasMessageBodies()
                    && message.getMessageBodies().hasSharerMessageBodies()
                    && message.getMessageBodies()
                                    .getSharerMessageBodies()
                                    .getSharerMessageBodyList()
                                    .size()
                            == 1
                    && message.getMessageBodies()
                            .getSharerMessageBodies()
                            .getSharerMessageBodyList()
                            .get(0)
                            .hasPairRequestMessage();

            if (!isPairRequestMessage) {
                // If the senderId is null, and the message is not a PairRequestMessage, it is invalid.
                // Drop the message.
                logger.debug("Dropping message");
                return;
            } else {
                // The senderId is only null in the case of a PairRequestMessage
                logger.debug("Found null sender, but for a PairRequest - allowing the message to go through");
            }
        }

        boolean isSharerMessage =
                message.hasMessageBodies() && message.getMessageBodies().hasSharerMessageBodies();

        ByteString receiverHash = message.getReceiver();
        DeRecIdentity receiverId = LibState.getInstance()
                .queryMessageHashAndSecretIdToIdentity(
                        receiverHash,
                        isSharerMessage
                                ? null
                                : new DeRecSecret.Id(message.getSecretId().toByteArray()));

        if (receiverId == null) {
            // Drop the message if we cannot find the receiverId
            logger.info("Could not find an entry in hashToIdentityMap for receiver "
                    + Base64.getEncoder().encodeToString(receiverHash.toByteArray()));
            logger.info("Dropping message");
            LibState.getInstance().printMessageHashToIdentityMap();
            return;
        }

        if (message.hasMessageBodies()) {
            if (message.getMessageBodies().hasHelperMessageBodies()) {
                parseHelperMessageBodies(
                        publicKeyId,
                        senderId,
                        receiverId,
                        secretId,
                        message.getMessageBodies().getHelperMessageBodies());
            } else if (message.getMessageBodies().hasSharerMessageBodies()) {
                parseSharerMessageBodies(
                        publicKeyId,
                        senderId,
                        receiverId,
                        secretId,
                        message.getMessageBodies().getSharerMessageBodies());
            }
        }
    }

    /**
     * Parse HelperMessageBodies within the DeRecMessage, and handles messages within HelperMessageBodies
     *
     * @param publicKeyId publicKeyId of the message receiver
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    SecretId extracted from the DeRecmessage
     * @param bodies      HelperMessageBodies
     */
    private void parseHelperMessageBodies(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            byte[] secretId,
            Derecmessage.DeRecMessage.HelperMessageBodies bodies) {
        logger.debug("in parseHelperMessageBodies");

        for (Derecmessage.DeRecMessage.HelperMessageBody body : bodies.getHelperMessageBodyList()) {
            if (body.hasPairResponseMessage()) {
                handlePairResponse(publicKeyId, senderId, receiverId, secretId, body.getPairResponseMessage());
            } else if (body.hasGetSecretIdsVersionsResponseMessage()) {
                handleGetSecretIdsVersionsResponse(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getGetSecretIdsVersionsResponseMessage());
                logger.debug("GetSecretIdsVersionsResponseMessage");
            } else if (body.hasErrorResponseMessage()) {
                logger.debug("ErrorResponseMessage");
            } else if (body.hasGetShareResponseMessage()) {
                logger.debug("GetShareResponseMessage");
                handleGetShareResponse(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getGetShareResponseMessage());
            } else if (body.hasUnpairResponseMessage()) {
                handleUnpairResponse(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getUnpairResponseMessage());
            } else if (body.hasStoreShareResponseMessage()) {
                handleStoreShareResponse(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getStoreShareResponseMessage());
            } else if (body.hasVerifyShareResponseMessage()) {
                handleVerifyShareResponse(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getVerifyShareResponseMessage());
            } else {
                logger.info("UNKNOWN helper message type");
            }
        }
    }

    /**
     * Parse SharerMessageBodies within the DeRecMessage, and handles messages within SharerMessageBodies
     *
     * @param publicKeyId publicKeyId of the message receiver
     * @param senderId    DeRecIdentity of the message sender
     * @param receiverId  DeRecIdentity of the message receiver
     * @param secretId    SecretId extracted from the DeRecmessage
     * @param bodies      SharerMessageBodies
     */
    private void parseSharerMessageBodies(
            int publicKeyId,
            DeRecIdentity senderId,
            DeRecIdentity receiverId,
            byte[] secretId,
            Derecmessage.DeRecMessage.SharerMessageBodies bodies) {
        logger.debug("in parseSharerMessageBodies");

        for (Derecmessage.DeRecMessage.SharerMessageBody body : bodies.getSharerMessageBodyList()) {
            if (body.hasPairRequestMessage()) {
                logger.debug("PairRequestMessage");
                handlePairRequest(publicKeyId, senderId, receiverId, secretId, body.getPairRequestMessage());
            } else if (body.hasGetShareRequestMessage()) {
                logger.debug("GetShareRequestMessage");
                handleGetShareRequest(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getGetShareRequestMessage());
            } else if (body.hasGetSecretIdsVersionsRequestMessage()) {
                logger.debug("GetSecretIdsVersionsRequestMessage");
                handleGetSecretIdsVersionsRequest(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getGetSecretIdsVersionsRequestMessage());
            } else if (body.hasStoreShareRequestMessage()) {
                logger.debug("StoreShareRequestMessage");
                handleStoreShareRequest(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getStoreShareRequestMessage());
            } else if (body.hasUnpairRequestMessage()) {
                logger.debug("UnpairRequestMessage");
                handleUnpairRequest(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getUnpairRequestMessage());
            } else if (body.hasVerifyShareRequestMessage()) {
                logger.debug("VerifyShareRequestMessage");
                handleVerifyShareRequest(
                        publicKeyId,
                        senderId,
                        receiverId,
                        new DeRecSecret.Id(secretId),
                        body.getVerifyShareRequestMessage());
            } else {
                logger.info("UNKNOWN sharer message type");
            }
            // Handle other message types
        }
    }
}
