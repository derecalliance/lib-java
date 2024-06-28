package org.derecalliance.derec.lib.impl;

import com.google.protobuf.InvalidProtocolBufferException;
import org.derecalliance.derec.lib.api.DeRecVersion;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Storeshare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Stream;

import static org.derecalliance.derec.lib.impl.CryptoPrimitives.dummyDecryptSecret;
import static org.derecalliance.derec.lib.impl.SecretImpl.parseSecretMessage;

//import static org.derecalliance.derec.lib.api.Secret.parseSecretMessage;
//import static org.derecalliance.derec.lib.CryptoPrimitives.dummyDecryptSecret;

public class RecoveryContext {
    HashMap<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> recoverableShares;
    HashMap<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> getShareRequestsSent;
    HashMap<DeRecSecret.Id, ArrayList<Integer>>  successfullyRecoveredVersions;
    HashMap<DeRecSecret.Id, HashMap<Integer, HashMap<DeRecHelperStatus, Storeshare.CommittedDeRecShare>>> retrievedCommittedDeRecShares;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    RecoveryContext() {
        recoverableShares = new HashMap<>();
        getShareRequestsSent = new HashMap<>();
        successfullyRecoveredVersions = new HashMap<>();
        retrievedCommittedDeRecShares = new HashMap<>();
    }
    private void addSecretToRecoveryContext(DeRecSecret.Id secretId) {
        if (!recoverableShares.containsKey(secretId)) {
            recoverableShares.put(secretId, new HashMap<>());
            getShareRequestsSent.put(secretId, new HashMap<>());
            successfullyRecoveredVersions.put(secretId, new ArrayList<>());
            retrievedCommittedDeRecShares.put(secretId, new HashMap<>());
        }
    }

    public void sendGetShareRequestsForUnrecoveredSecrets(SecretImpl dummySecretForRecovering) {
        for (var secretId : recoverableShares.keySet()) {
            DeRecSecret secretIdToRecover = LibState.getInstance().getMeSharer().getSecret(secretId);
            if (secretIdToRecover != null || secretIdToRecover.isRecovering()) {


            } else {
                logger.debug("Not processing secret id " + secretId);
            }
        }
    }

    public void helperHasVersions(DeRecSecret.Id secretIdToRecover, DeRecHelperStatus helperStatus, ArrayList<Integer> versionNumbers) {
        addSecretToRecoveryContext(secretIdToRecover);
        logger.debug("in helperHasVersions: secretIdToRecover: " + secretIdToRecover + ", " +
                "Helper: " + helperStatus.getId().getName() + ", Versions: " + versionNumbers);
        for (Integer versionNumber: versionNumbers) {
            // If this is the first version for this secret id, initialize the recoverableShares and
            // getShareRequestsSent data structures
            if (!recoverableShares.get(secretIdToRecover).containsKey(versionNumber)) {
                recoverableShares.get(secretIdToRecover).put(versionNumber, new ArrayList<>());
                getShareRequestsSent.get(secretIdToRecover).put(versionNumber, new ArrayList<>());
            }

            if (!recoverableShares.get(secretIdToRecover).get(versionNumber).contains(helperStatus)) {
                recoverableShares.get(secretIdToRecover).get(versionNumber).add(helperStatus);
            }
        }
        logger.debug("after processing helperHasVersions, map is: " + this);
    }

    public HashMap<Integer, ArrayList<DeRecHelperStatus>> evaluate(DeRecSecret.Id recoveringSecretId) {
            HashMap<Integer, ArrayList<DeRecHelperStatus>> recoverableVersions = new HashMap<>();
            if (recoverableShares.get(recoveringSecretId) != null) {
                for (Map.Entry<Integer, ArrayList<DeRecHelperStatus>> versionEntry :
                        recoverableShares.get(recoveringSecretId).entrySet()) {
                    int versionNumber = versionEntry.getKey();
                    // if this version is already recovered, don't re-evaluate it again
                    if (successfullyRecoveredVersions.get(recoveringSecretId).contains(versionNumber)) {
                        continue;
                    }
                    if (versionEntry.getValue().size() >= LibState.getInstance().getMinNumberOfHelpersForRecovery()) {
                        recoverableVersions.put(versionNumber, recoverableShares.get(recoveringSecretId).get(versionNumber));
                    }
                }
            }
            return(recoverableVersions);
    }

    public void evaluateAndSendGetShareRequests(DeRecSecret.Id dummySecretId) {
        // TODO: Check if the secretId for which we are sending Get Share Request is already recovered. If that's the
        //  case, don't send the request.
        DeRecSecret dummySecret = LibState.getInstance().getMeSharer().getSecret(dummySecretId);

        if (dummySecret.isRecovering() == false) {
            logger.debug("evaluateAndSendGetShareRequests: returning because isRecovering=false: " + dummySecretId);
            return;
        }

        for (DeRecSecret.Id recoveringSecretId : recoverableShares.keySet()) {
            HashMap<Integer, ArrayList<DeRecHelperStatus>> sendMap = evaluate(recoveringSecretId);
            if (!sendMap.isEmpty()) {
                logger.debug("*********  in evaluateAndSendGetShareRequests sendMap is present *********");
            }
            for (HashMap.Entry<Integer, ArrayList<DeRecHelperStatus>> sendEntry : sendMap.entrySet()) {
                int versionNumber = sendEntry.getKey();
                ArrayList<DeRecHelperStatus> toList = sendEntry.getValue();

                logger.debug("---------------------------------------------In evaluateAndSendGetShareRequests: For " +
                        "version: " + versionNumber + " toList size: " + toList.size());
                for (DeRecHelperStatus helperToSend : toList) {
                    logger.debug("HelperToSend: " + helperToSend + ", name: " + helperToSend.getId().getName());
                }
                logger.debug("And getShareRequestsSent size is: " + getShareRequestsSent.get(recoveringSecretId).get(versionNumber).size());
                for (var hs : getShareRequestsSent.get(recoveringSecretId).get(versionNumber)) {
                    logger.debug("hs: " + hs + ", name: " + hs.getId().getName());
                }
                logger.debug("----");


                for (DeRecHelperStatus helperToSend : toList) {

                    if (!getShareRequestsSent.get(recoveringSecretId).get(versionNumber).contains(helperToSend)) {
                        // Remember that we sent this request out, so we don't re-send this request multiple times
                        // Ideally, this should be done *after* we send the message. But for testing when we run the
                        // timer every 1 second, there are situations when the httpClient doesn't send a request in 1
                        // second and that results in sending multiple requests to the same helper.
                        getShareRequestsSent.get(recoveringSecretId).get(versionNumber).add(helperToSend);

                        // send GetShare message
                        GetShareMessages.sendGetShareRequestMessage(
                                LibState.getInstance().getMeSharer().getMyLibId().getMyId(), helperToSend.getId(),
                                dummySecretId, recoveringSecretId,
                                LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(),
                                versionNumber);
                        logger.debug("Sent sendGetShareRequestMessage to " + helperToSend + ", name: " + helperToSend.getId().getName() + " for recoveringSecretId: " + recoveringSecretId);

                    }
                }

                logger.debug("After processing - In evaluateAndSendGetShareRequests");
                logger.debug("And getShareRequestsSent size is: " + getShareRequestsSent.get(recoveringSecretId).get(versionNumber).size());
                for (var hs : getShareRequestsSent.get(recoveringSecretId).get(versionNumber)) {
                    logger.debug("hs: " + hs + ", name: " + hs.getId().getName());
                }
                logger.debug("----");

            }
        }
    }

    public void versionRecovered(DeRecSecret.Id secretId, int versionNumber) {
        successfullyRecoveredVersions.get(secretId).add(versionNumber);
    }


    public boolean saveRetrievedCommittedDeRecShare(DeRecSecret.Id secretId, Integer versionNumber,
                                                    DeRecHelperStatus helperStatus,
                                                Storeshare.CommittedDeRecShare committedDeRecShare) {
        logger.debug("In saveRetrievedCommittedDeRecShare for version # " + versionNumber);
        // Store the retrieved committedDeRecShare
        if (!retrievedCommittedDeRecShares.containsKey(secretId)) {
            retrievedCommittedDeRecShares.put(secretId, new HashMap<>());
        }
        if (!retrievedCommittedDeRecShares.get(secretId).containsKey(versionNumber)) {
            retrievedCommittedDeRecShares.get(secretId).put(versionNumber, new HashMap<>());
        }
        retrievedCommittedDeRecShares.get(secretId).get(versionNumber).put(helperStatus, committedDeRecShare);

        // Attempt tp recombine
        return attemptToRecombine(secretId, versionNumber);
    }

    public boolean attemptToRecombine(DeRecSecret.Id secretId, Integer versionNumber) {
        try {
            logger.debug("Attempting to recombine");

            for (var s : LibState.getInstance().getMeSharer().getSecrets()) {
                logger.debug("***************** Before recovery secret: " + s.getSecretId() + ", recovering: " + s.isRecovering());
            }

            // Find out the current secret (in the context of the recovering user) so that we can populate the
            // version and helpers into that.
            var currentSecret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);

            // If the secret has already recovered a version, then only allow newer versions to recover
            if (!currentSecret.isRecovering()) {
                if (versionNumber <= currentSecret.getMaxVersionNumber()) {
                    logger.debug("VersionImpl " + versionNumber + "is lesser than current version of " + currentSecret.getMaxVersionNumber());
                    return false;
                }
            }

            logger.debug("created merkledVss");
            logger.debug("Dump 1" + toString());
            byte[] valueToProtect = LibState.getInstance().getDerecCryptoImpl().recover(secretId.getBytes(), versionNumber,
                    retrievedCommittedDeRecShares.get(secretId).get(versionNumber).values().stream().map(cds -> cds.toByteArray()).toList());
            if (valueToProtect == null || valueToProtect.length == 0) {
                logger.debug("Combine sent no data");
                return false;
            }
            logger.debug("combined valueToProtect successfully, len: " + valueToProtect.length);

            // Now that we have successfully recombined, remove the shares from retrievedCommittedDeRecShares
            retrievedCommittedDeRecShares.get(secretId).put(versionNumber, new HashMap<>());
            parseSecretMessage(LibState.getInstance().getMeSharer().getRecoveredState(), secretId, valueToProtect);



            // TODO TODORECOVER move this to when user clicks on "recovery complete" button
//            LibState.getInstance().getMeSharer().installRecoveredSecret(recoveredSecret);
//            // Recalculate the shares for all versions now
//            for (DeRecVersion deRecVersion: currentSecret.getVersions().values().stream().toList()) {
//                VersionImpl version = (VersionImpl) deRecVersion;
//                version.createShares();
//            }


            logger.debug("--- really done---");

            for (var s : LibState.getInstance().getMeSharer().getSecrets()) {
                logger.debug("***************** Before recovery secret: " + s.getSecretId() + ", recovering: " + s.isRecovering());
            }
            return true;
        } catch (Exception ex) {
            logger.error("Exception in attemptToRecombine");
            ex.printStackTrace();
        }

        return false;


    }
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("RecoverableShares:\n");

        for (Map.Entry<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> secretEntry :
                recoverableShares.entrySet()) {
            sb.append("Secret Id: ").append(secretEntry.getKey().toString()).append("\n");

            for (Map.Entry<Integer, ArrayList<DeRecHelperStatus>> versionEntry : secretEntry.getValue().entrySet()) {
                sb.append("  VersionImpl Number: ").append(versionEntry.getKey()).append("\n");
                ArrayList<DeRecHelperStatus> helperStatuses = versionEntry.getValue();
                for (DeRecHelperStatus helperStatus: helperStatuses) {
                    sb.append("  Helper: ").append(helperStatus.getId().getName()).append("\n");
                }
            }
        }

        sb.append("\n\nretrievedCommittedDeRecShares:\n");

        for (Map.Entry<DeRecSecret.Id, HashMap<Integer, HashMap<DeRecHelperStatus, Storeshare.CommittedDeRecShare>>> secretEntry :
                retrievedCommittedDeRecShares.entrySet()) {
            sb.append("Secret Id: ").append(secretEntry.getKey().toString()).append("\n");

            for (Map.Entry<Integer, HashMap<DeRecHelperStatus, Storeshare.CommittedDeRecShare>> versionEntry : secretEntry.getValue().entrySet()) {
                sb.append("  VersionImpl Number: ").append(versionEntry.getKey()).append("\n");
                HashMap<DeRecHelperStatus, Storeshare.CommittedDeRecShare> map = versionEntry.getValue();
                for (DeRecHelperStatus helperStatus: map.keySet()) {
                    try {
                        Storeshare.DeRecShare deRecShare = Storeshare.DeRecShare.parseFrom(map.get(helperStatus).getDeRecShare());
                        sb.append("  Helper: ").append(helperStatus.getId().getName()).append(": ");
                        sb.append(" Ver Descr:").append(deRecShare.getVersionDescription());
                        sb.append(" Ver num:").append(deRecShare.getVersion());
                    } catch (Exception ex) {
                        logger.debug("Exception occurred ", ex);
                    }

                }
            }
        }
        return sb.toString();
    }
}
