package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
//import org.derecalliance.derec.lib.LibState;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

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

class MessageParser {
    static Logger logger = LoggerFactory.getLogger(MessageParser.class.getName());

    public static void printDeRecMessage(Derecmessage.DeRecMessage message, String description) {
         String senderDigest = Base64.getEncoder().encodeToString(message.getSender().toByteArray());
         String receiverDigest = Base64.getEncoder().encodeToString(message.getReceiver().toByteArray());
         String secret = Base64.getEncoder().encodeToString(message.getSecretId().toByteArray());
        DeRecIdentity senderId = LibState.getInstance().messageHashToIdentityMap.get(message.getSender());
        DeRecIdentity receiverId = LibState.getInstance().messageHashToIdentityMap.get(message.getReceiver());
        LibState.getInstance().printMessageHashToIdentityMap();

        if (senderId == null) {
            logger.error("printDeRecMessage: Could not find an entry in hashToIdentityMap for sender " + senderDigest);
        }
        if (receiverId == null) {
            logger.error("printDeRecMessage: Could not find an entry in hashToIdentityMap for receiver " + receiverDigest);
        }
         logger.info(description + ",Sender: " + senderDigest + " ("  +
                 (senderId == null ? "unknown" : senderId.getName()) + "), Receiver: " + receiverDigest + " (" +
                         (receiverId == null ? "unknown" : receiverId.getName() + "), Secret: " + secret));


         if (message.hasMessageBodies()) {
             if (message.getMessageBodies().hasSharerMessageBodies()) {
                 for (Derecmessage.DeRecMessage.SharerMessageBody body : message.getMessageBodies().getSharerMessageBodies().getSharerMessageBodyList()) {
                    if (body.hasPairRequestMessage()) {
                        logger.info("PairRequestMessage");
                        Pair.PairRequestMessage pairMsg = body.getPairRequestMessage();
                        String encryptionKey = pairMsg.getPublicEncryptionKey();
                        logger.info(" - encryptionKey: " + encryptionKey);

                    } else if (body.hasGetShareRequestMessage()) {
                        logger.info("GetShareRequestMessage for secretId: " + body.getGetShareRequestMessage().getSecretId() + ", " +
                                "version number: " + body.getGetShareRequestMessage().getShareVersion());
                    } else if (body.hasGetSecretIdsVersionsRequestMessage()) {
                        logger.info("GetSecretIdsVersionsRequestMessage");
                    } else if (body.hasStoreShareRequestMessage()) {
                        logger.info("StoreShareRequestMessage");
                        Storeshare.StoreShareRequestMessage msg = body.getStoreShareRequestMessage();
                        logger.info(" - VersionImpl: " + msg.getVersion() + ", ShareImpl size: " + msg.getShare().size() + ", KeepList: " + msg.getKeepListList());
                        try {
                            CommittedDeRecShare committedDeRecShare =
                                   new CommittedDeRecShare(Storeshare.CommittedDeRecShare.parseFrom(msg.getShare()));
//                            System.out.println("Committed DeRecShare (recd) is: " + committedDeRecShare.toString());
                        } catch (InvalidProtocolBufferException ex) {
                            logger.error("Exception in trying to parse the incoming share as a committed derec " +
                                    "share");
                            ex.printStackTrace();
                        }
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
                 for (Derecmessage.DeRecMessage.HelperMessageBody body : message.getMessageBodies().getHelperMessageBodies().getHelperMessageBodyList()) {
                     if (body.hasPairResponseMessage()) {
                         logger.info("PairResponseMessage");
                     } else if (body.hasGetSecretIdsVersionsResponseMessage()) {
                         logger.info("GetSecretIdsVersionsResponseMessage");
                         logger.info(" - ****** SECRETLIST ******");
                         for (Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList list : body.getGetSecretIdsVersionsResponseMessage().getSecretListList()){
                             logger.info(" - - Secret ID " +
                                             Base64.getEncoder().encodeToString(list.getSecretId().toByteArray()));
                             for (int versionNumber : list.getVersionsList()) {
                                 logger.info(" - - - version #: " + versionNumber);
                             }
                         }
                     } else if (body.hasErrorResponseMessage()) {
                         logger.info("ErrorResponseMessage");
                     } else if (body.hasGetShareResponseMessage()) {
                         logger.info("GetShareResponseMessage, Result: " + body.getGetShareResponseMessage().getResult().getStatus().toString());
//                         System.out.println("ShareImpl size: " + body.getGetShareResponseMessage().getCommittedDeRecShare().getDeRecShare().size());
//                         System.out.println("Commitment: " + body.getGetShareResponseMessage().getCommittedDeRecShare().getCommitment());
                         try {
                             Storeshare.DeRecShare shareMsg =
                                     Storeshare.DeRecShare.parseFrom(body.getGetShareResponseMessage().getCommittedDeRecShare().getDeRecShare());
                             logger.info("Version: " + shareMsg.getVersion());
                         } catch (InvalidProtocolBufferException ex) {
                             logger.error("Exception in trying to parse the incoming share as a derec share");
                             ex.printStackTrace();
                         }
                     } else if (body.hasUnpairResponseMessage()) {
                         logger.info("UnpairResponseMessage");
                     } else if (body.hasStoreShareResponseMessage()) {
                         logger.info("StoreShareResponseMessage");
                         Storeshare.StoreShareResponseMessage msg = body.getStoreShareResponseMessage();
                         logger.info("Result: " + msg.getResult().getStatus().toString() + ", memo: " + msg.getResult().getMemo());
                     } else if (body.hasVerifyShareResponseMessage()) {
                         logger.info("VerifyShareResponseMessage");
                         Verify.VerifyShareResponseMessage msg = body.getVerifyShareResponseMessage();
                         logger.info("VersionImpl: " + msg.getVersion() + "Result: " + msg.getResult().getStatus().toString() + ", memo: " + msg.getResult().getMemo());
                     } else {
                         logger.info("UNKNOWN helper message type");
                     }
                 }
             }
         }
     }
     void parseMessage(int publicKeyId, Derecmessage.DeRecMessage message) {

         printDeRecMessage(message, "Received ");
         if (LibState.getInstance().getMeHelper().isPaused()) {
             logger.debug("Ignoring message because I'm paused");
             return;
         }
         byte[] secretId = message.getSecretId().toByteArray();
         ByteString senderHash = message.getSender();
         DeRecIdentity senderId = LibState.getInstance().messageHashToIdentityMap.get(senderHash);
         if (senderId == null) {
             System.out.println("Could not find an entry in hashToIdentityMap for sender " + senderHash);

             LibState.getInstance().printMessageHashToIdentityMap();
             if (!(message.hasMessageBodies() &&
                     message.getMessageBodies().hasSharerMessageBodies() &&
                     message.getMessageBodies().getSharerMessageBodies().getSharerMessageBodyList().size() == 1 &&
                     message.getMessageBodies().getSharerMessageBodies().getSharerMessageBodyList().get(0).hasPairRequestMessage())) {
                 logger.debug("Dropping message");
                 return;
             } else {
                 logger.debug("Found null sender, but for a PairRequest - allowing the message to go through");
             }
         }
         ByteString receiverHash = message.getReceiver();
         DeRecIdentity receiverId = LibState.getInstance().messageHashToIdentityMap.get(receiverHash);
         if (receiverId == null) {
             logger.info("Could not find an entry in hashToIdentityMap for receiver " + receiverHash);
             logger.info("Dropping message");
             LibState.getInstance().printMessageHashToIdentityMap();
             return;
         }

        if (message.hasMessageBodies()) {
            if (message.getMessageBodies().hasHelperMessageBodies()) {
                parseHelperMessageBodies(publicKeyId, senderId, receiverId, secretId,
                message.getMessageBodies().getHelperMessageBodies());
            } else if (message.getMessageBodies().hasSharerMessageBodies()) {
                parseSharerMessageBodies(publicKeyId, senderId, receiverId, secretId,
                        message.getMessageBodies().getSharerMessageBodies());
            }
        }
    }

    private void parseHelperMessageBodies(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId,
                                          byte[] secretId,
                                          Derecmessage.DeRecMessage.HelperMessageBodies bodies) {
        logger.debug("in parseHelperMessageBodies");
        for (Derecmessage.DeRecMessage.HelperMessageBody body : bodies.getHelperMessageBodyList()) {
            if (body.hasPairResponseMessage()) {
                handlePairResponse(publicKeyId, senderId, receiverId, secretId, body.getPairResponseMessage());
            } else if (body.hasGetSecretIdsVersionsResponseMessage()) {
                handleGetSecretIdsVersionsResponse(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getGetSecretIdsVersionsResponseMessage());
                logger.debug("GetSecretIdsVersionsResponseMessage");
            } else if (body.hasErrorResponseMessage()) {
                logger.debug("ErrorResponseMessage");
            } else if (body.hasGetShareResponseMessage()) {
                logger.debug("GetShareResponseMessage");
                handleGetShareResponse(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),body.getGetShareResponseMessage());
            } else if (body.hasUnpairResponseMessage()) {
                handleUnpairResponse(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),body.getUnpairResponseMessage());
            } else if (body.hasStoreShareResponseMessage()) {
                handleStoreShareResponse(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getStoreShareResponseMessage());
            } else if (body.hasVerifyShareResponseMessage()) {
                handleVerifyShareResponse(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getVerifyShareResponseMessage());
            } else {
                logger.info("UNKNOWN helper message type");
            }
        }
    }
    private void parseSharerMessageBodies(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, byte[] secretId,
                                          Derecmessage.DeRecMessage.SharerMessageBodies bodies) {
        logger.debug("in parseSharerMessageBodies");

        for (Derecmessage.DeRecMessage.SharerMessageBody body : bodies.getSharerMessageBodyList()) {
            if (body.hasPairRequestMessage()) {
                handlePairRequest(publicKeyId, senderId, receiverId, secretId, body.getPairRequestMessage());
            } else if (body.hasGetShareRequestMessage()) {
                logger.debug("GetShareRequestMessage");
                handleGetShareRequest(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),body.getGetShareRequestMessage());
            } else if (body.hasGetSecretIdsVersionsRequestMessage()) {
                handleGetSecretIdsVersionsRequest(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId), body.getGetSecretIdsVersionsRequestMessage());
            } else if (body.hasStoreShareRequestMessage()) {
                handleStoreShareRequest(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getStoreShareRequestMessage());
            } else if (body.hasUnpairRequestMessage()) {
                handleUnpairRequest(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getUnpairRequestMessage());
            } else if (body.hasVerifyShareRequestMessage()) {
                handleVerifyShareRequest(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getVerifyShareRequestMessage());
            } else {
                logger.info("UNKNOWN sharer message type");
            }
            // Handle other message types
        }
    }


}
