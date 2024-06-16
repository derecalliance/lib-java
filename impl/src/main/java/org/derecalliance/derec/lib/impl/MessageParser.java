package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
//import org.derecalliance.derec.lib.LibState;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.*;

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

     public static void printDeRecMessage(Derecmessage.DeRecMessage message, String description) {
         System.out.println("\n" + description + " Message:");
         System.out.println("Sender: " + Base64.getEncoder().encodeToString(message.getSender().toByteArray()));
         System.out.println("Receiver: " + Base64.getEncoder().encodeToString(message.getReceiver().toByteArray()));
         System.out.println("Secret: " + Base64.getEncoder().encodeToString(message.getSecretId().toByteArray()));

         if (message.hasMessageBodies()) {
             if (message.getMessageBodies().hasSharerMessageBodies()) {
                 for (Derecmessage.DeRecMessage.SharerMessageBody body : message.getMessageBodies().getSharerMessageBodies().getSharerMessageBodyList()) {
                    if (body.hasPairRequestMessage()) {
                        System.out.println("PairRequestMessage");
                        Pair.PairRequestMessage pairMsg = body.getPairRequestMessage();
                        String encryptionKey = pairMsg.getPublicEncryptionKey();
                        System.out.println("    encryptionKey: " + encryptionKey);
                    } else if (body.hasGetShareRequestMessage()) {
                        System.out.println("GetShareRequestMessage");
                        System.out.println(" for secretId: " + body.getGetShareRequestMessage().getSecretId() + ", " +
                                "version number: " + body.getGetShareRequestMessage().getShareVersion());
                    } else if (body.hasGetSecretIdsVersionsRequestMessage()) {
                        System.out.println("GetSecretIdsVersionsRequestMessage");
                    } else if (body.hasStoreShareRequestMessage()) {
                        System.out.println("StoreShareRequestMessage");
                        Storeshare.StoreShareRequestMessage msg = body.getStoreShareRequestMessage();
                        System.out.println("VersionImpl: " + msg.getVersion());
                        System.out.println("ShareImpl size: " + msg.getShare().size());
                        System.out.println("KeepList: " + msg.getKeepListList());
                        try {
                            CommittedDeRecShare committedDeRecShare =
                                   new CommittedDeRecShare(Storeshare.CommittedDeRecShare.parseFrom(msg.getShare()));
//                            System.out.println("Committed DeRecShare (recd) is: " + committedDeRecShare.toString());
                        } catch (InvalidProtocolBufferException ex) {
                            System.out.println("Exception in trying to parse the incoming share as a committed derec " +
                                    "share");
                            ex.printStackTrace();
                        }
                    } else if (body.hasUnpairRequestMessage()) {
                        System.out.println("UnpairRequestMessage");
                    } else if (body.hasVerifyShareRequestMessage()) {
                        System.out.println("VerifyShareRequestMessage");
                        Verify.VerifyShareRequestMessage msg = body.getVerifyShareRequestMessage();
                        System.out.println("VersionImpl: " + msg.getVersion());
                    } else {
                        System.out.println("UNKNOWN sharer message type");
                    }
                 }
             } else if (message.getMessageBodies().hasHelperMessageBodies()) {
                 for (Derecmessage.DeRecMessage.HelperMessageBody body : message.getMessageBodies().getHelperMessageBodies().getHelperMessageBodyList()) {
                     if (body.hasPairResponseMessage()) {
                         System.out.println("PairResponseMessage");
                     } else if (body.hasGetSecretIdsVersionsResponseMessage()) {
                         System.out.println("GetSecretIdsVersionsResponseMessage");
                         System.out.println("****** SECRETLIST ******");
                         for (Secretidsversions.GetSecretIdsVersionsResponseMessage.VersionList list : body.getGetSecretIdsVersionsResponseMessage().getSecretListList()){
                             System.out.println("Secret ID " +
                                             Base64.getEncoder().encodeToString(list.getSecretId().toByteArray()));
                             for (int versionNumber : list.getVersionsList()) {
                                 System.out.println("    version #: " + versionNumber);
                             }
                         }
                     } else if (body.hasErrorResponseMessage()) {
                         System.out.println("ErrorResponseMessage");
                     } else if (body.hasGetShareResponseMessage()) {
                         System.out.println("GetShareResponseMessage");
                         System.out.println("Result: " + body.getGetShareResponseMessage().getResult().getStatus().toString());
                         System.out.println("ShareImpl size: " + body.getGetShareResponseMessage().getCommittedDeRecShare().getDeRecShare().size());
                         System.out.println("Commitment: " + body.getGetShareResponseMessage().getCommittedDeRecShare().getCommitment());
                         try {
                             Storeshare.DeRecShare shareMsg =
                                     Storeshare.DeRecShare.parseFrom(body.getGetShareResponseMessage().getCommittedDeRecShare().getDeRecShare());
                             System.out.println("Version: " + shareMsg.getVersion());
                         } catch (InvalidProtocolBufferException ex) {
                             System.out.println("Exception in trying to parse the incoming share as a derec share");
                             ex.printStackTrace();
                         }
                     } else if (body.hasUnpairResponseMessage()) {
                         System.out.println("UnpairResponseMessage");
                     } else if (body.hasStoreShareResponseMessage()) {
                         System.out.println("StoreShareResponseMessage");
                         Storeshare.StoreShareResponseMessage msg = body.getStoreShareResponseMessage();
                         System.out.println("Result: " + msg.getResult().getStatus().toString() + ", memo: " + msg.getResult().getMemo());
                     } else if (body.hasVerifyShareResponseMessage()) {
                         System.out.println("VerifyShareResponseMessage");
                         Verify.VerifyShareResponseMessage msg = body.getVerifyShareResponseMessage();
                         System.out.println("VersionImpl: " + msg.getVersion() + "Result: " + msg.getResult().getStatus().toString() + ", memo: " + msg.getResult().getMemo());
                     } else {
                         System.out.println("UNKNOWN helper message type");
                     }
                 }
             }
         }
     }
     void parseMessage(int publicKeyId, Derecmessage.DeRecMessage message) {
         printDeRecMessage(message, "Received ");
         if (LibState.getInstance().getMeHelper().isPaused()) {
             System.out.println("Ignoring message because I'm paused");
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
                 System.out.println("Dropping message");
                 return;
             } else {
                 System.out.println("Found null sender, but for a PairRequest - allowing the message to go through");
             }
         }
         ByteString receiverHash = message.getReceiver();
         DeRecIdentity receiverId = LibState.getInstance().messageHashToIdentityMap.get(receiverHash);
         if (receiverId == null) {
             System.out.println("Could not find an entry in hashToIdentityMap for receiver " + receiverHash);
             System.out.println("Dropping message");
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
        System.out.println("in parseHelperMessageBodies");
        for (Derecmessage.DeRecMessage.HelperMessageBody body : bodies.getHelperMessageBodyList()) {
            if (body.hasPairResponseMessage()) {
                handlePairResponse(publicKeyId, senderId, receiverId, secretId, body.getPairResponseMessage());
            } else if (body.hasGetSecretIdsVersionsResponseMessage()) {
                handleGetSecretIdsVersionsResponse(publicKeyId, senderId, receiverId, new DeRecSecret.Id(secretId),
                        body.getGetSecretIdsVersionsResponseMessage());
                System.out.println("GetSecretIdsVersionsResponseMessage");
            } else if (body.hasErrorResponseMessage()) {
                System.out.println("ErrorResponseMessage");
            } else if (body.hasGetShareResponseMessage()) {
                System.out.println("GetShareResponseMessage");
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
                System.out.println("UNKNOWN helper message type");
            }
        }
    }
    private void parseSharerMessageBodies(int publicKeyId, DeRecIdentity senderId, DeRecIdentity receiverId, byte[] secretId,
                                          Derecmessage.DeRecMessage.SharerMessageBodies bodies) {
        System.out.println("in parseSharerMessageBodies");

        for (Derecmessage.DeRecMessage.SharerMessageBody body : bodies.getSharerMessageBodyList()) {
            if (body.hasPairRequestMessage()) {
                handlePairRequest(publicKeyId, senderId, receiverId, secretId, body.getPairRequestMessage());
            } else if (body.hasGetShareRequestMessage()) {
                System.out.println("GetShareRequestMessage");
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
                System.out.println("UNKNOWN sharer message type");
            }
            // Handle other message types
        }
    }


}
