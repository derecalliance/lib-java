package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Storeshare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.derecalliance.derec.lib.impl.SecretImpl.parseSecretMessage;

/**
 * Contains the methods and data structures necessary for recovering a secret.
 */
public class RecoveryContext {
    HashMap<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> recoverableShares;
    HashMap<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> getShareRequestsSent;
    HashMap<DeRecSecret.Id, ArrayList<Integer>> successfullyRecoveredVersions;
    HashMap<DeRecSecret.Id, HashMap<Integer, HashMap<DeRecHelperStatus, Storeshare.CommittedDeRecShare>>> retrievedCommittedDeRecShares;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    RecoveryContext() {
        recoverableShares = new HashMap<>();
        getShareRequestsSent = new HashMap<>();
        successfullyRecoveredVersions = new HashMap<>();
        retrievedCommittedDeRecShares = new HashMap<>();
    }

    /**
     * Adds a secret to this class by updating the necessary local data structures.
     *
     * @param secretId secretId of the secret
     */
    private void addSecretToRecoveryContext(DeRecSecret.Id secretId) {
        if (!recoverableShares.containsKey(secretId)) {
            recoverableShares.put(secretId, new HashMap<>());
            getShareRequestsSent.put(secretId, new HashMap<>());
            successfullyRecoveredVersions.put(secretId, new ArrayList<>());
            retrievedCommittedDeRecShares.put(secretId, new HashMap<>());
        }
    }

    /**
     * Registers what versions of a secret a Helper has
     *
     * @param secretIdToRecover SecretId of the secret a Helper has stored versions of
     * @param helperStatus      DeRecHelperStatus object of the Helper
     * @param versionNumbers    List of version numbers stored by the Helper
     */
    public void helperHasVersions(DeRecSecret.Id secretIdToRecover, DeRecHelperStatus helperStatus, ArrayList<Integer> versionNumbers) {
        addSecretToRecoveryContext(secretIdToRecover);
        logger.debug("in helperHasVersions: secretIdToRecover: " + secretIdToRecover + ", " +
                "Helper: " + helperStatus.getId().getName() + ", Versions: " + versionNumbers);
        for (Integer versionNumber : versionNumbers) {
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

    /**
     * Evaluate whether we have enough shares to recover a given secret
     *
     * @param recoveringSecretId SecretId of the secret
     * @return HashMap of the versions deemed recoverable, and what Helpers have that version
     */
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
                // if we have enough shares for a given version number, add that version to the recoverableVersions map
                if (versionEntry.getValue().size() >= LibState.getInstance().getMinNumberOfHelpersForRecovery()) {
                    recoverableVersions.put(versionNumber, recoverableShares.get(recoveringSecretId).get(versionNumber));
                }
            }
        }
        return (recoverableVersions);
    }

    /**
     * Evaluate whether we can recover a secret and send GetShareRequestMessages accordingly.
     *
     * @param dummySecretId SecretId of the secret being used for recovery mode
     */
    public void evaluateAndSendGetShareRequests(DeRecSecret.Id dummySecretId) {
        // TODO: Check if the secretId for which we are sending Get Share Request is already recovered. If that's the
        //  case, don't send the request.

        // This dummySecret is needed for message sending, because we communicate in the context of the secret used
        // for recovery mode, but ask for shares of our previous secret ids.
        SecretImpl dummySecret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(dummySecretId);
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
                                dummySecret.getLibId().getMyId(), helperToSend.getId(),
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

    /**
     * Upon receiving a CommittedDerecShare in the GetShareResponseMessage, save that share in the
     * retrievedCommittedDeRecShares map to attempt recovery.
     *
     * @param secretId            SecretId of the share received
     * @param versionNumber       Version number of the share received
     * @param helperStatus        HelperStatus that we received the share from
     * @param committedDeRecShare The CommittedDeRecShare from the GetShareResponseMessage
     * @return Boolean whether combining shares and recovering a version was successful
     */
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

        // Attempt to recombine
        return attemptToRecombine(secretId, versionNumber);
    }

    /**
     * Attempts to recover a version of a secret. Calls the crypto library's recover() method to combine received shares
     * using Shamir's secret sharing algorithm.
     *
     * @param secretId      SecretId to recover
     * @param versionNumber Version number to recover
     * @return Whether recovery was successful
     */
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
                // We are unable to recover the version
                logger.debug("Combine sent no data");
                return false;
            }
            logger.debug("combined valueToProtect successfully, len: " + valueToProtect.length);

            // Now that we have successfully recombined, remove the shares from retrievedCommittedDeRecShares
            retrievedCommittedDeRecShares.get(secretId).put(versionNumber, new HashMap<>());
            parseSecretMessage(LibState.getInstance().getMeSharer(), LibState.getInstance().getMeSharer().getRecoveredState(), secretId, valueToProtect);
            logger.debug("--- really done---");

            for (var s : LibState.getInstance().getMeSharer().getSecrets()) {
                logger.debug("***************** Before recovery secret: " + s.getSecretId() + ", recovering: " + s.isRecovering());
            }
            return true;
        } catch (Exception ex) {
            logger.error("Exception in attemptToRecombine", ex);
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
                for (DeRecHelperStatus helperStatus : helperStatuses) {
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
                for (DeRecHelperStatus helperStatus : map.keySet()) {
                    try {
                        Storeshare.DeRecShare deRecShare = Storeshare.DeRecShare.parseFrom(map.get(helperStatus).getDeRecShare());
                        sb.append("  Helper: ").append(helperStatus.getId().getName()).append(": ");
                        sb.append(" Ver Descr:").append(deRecShare.getVersionDescription());
                        sb.append(" Ver num:").append(deRecShare.getVersion());
                    } catch (Exception ex) {
                        logger.debug("Exception in RecoveryContext toString ", ex);
                    }

                }
            }
        }
        return sb.toString();
    }
}
