package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecVersion;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;

import java.util.*;

import static org.derecalliance.derec.lib.impl.CryptoPrimitives.dummyDecryptSecret;
import static org.derecalliance.derec.lib.impl.SecretImpl.parseSecretMessage;

//import static org.derecalliance.derec.lib.api.Secret.parseSecretMessage;
//import static org.derecalliance.derec.lib.CryptoPrimitives.dummyDecryptSecret;

public class RecoveryContext {
    HashMap<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> recoverableShares;
    HashMap<DeRecSecret.Id, HashMap<Integer, ArrayList<DeRecHelperStatus>>> getShareRequestsSent;
    HashMap<DeRecSecret.Id, ArrayList<Integer>>  successfullyRecoveredVersions;
    HashMap<DeRecSecret.Id, HashMap<Integer, HashMap<DeRecHelperStatus, CommittedDeRecShare>>> retrievedCommittedDeRecShares;

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

    public void helperHasVersions(DeRecSecret.Id secretId, DeRecHelperStatus helperStatus, ArrayList<Integer> versionNumbers) {
        addSecretToRecoveryContext(secretId);
        System.out.println("in helperHasVersions: secretId: " + secretId + ", Helper: " + helperStatus.getId().getName() + ", Versions: " + versionNumbers);
        for (Integer versionNumber: versionNumbers) {
            if (!recoverableShares.get(secretId).containsKey(versionNumber)) {
                recoverableShares.get(secretId).put(versionNumber, new ArrayList<>());
                getShareRequestsSent.get(secretId).put(versionNumber, new ArrayList<>());
            }
            if (!recoverableShares.get(secretId).get(versionNumber).contains(helperStatus)) {
                recoverableShares.get(secretId).get(versionNumber).add(helperStatus);
            }
        }
        System.out.println("after processing helperHasVersions, map is: " + this);
    }

    public HashMap<Integer, ArrayList<DeRecHelperStatus>> evaluate(DeRecSecret.Id secretId) {
            HashMap<Integer, ArrayList<DeRecHelperStatus>> recoverableVersions = new HashMap<>();
            if (recoverableShares.get(secretId) != null) {
                for (Map.Entry<Integer, ArrayList<DeRecHelperStatus>> versionEntry :
                        recoverableShares.get(secretId).entrySet()) {
                    int versionNumber = versionEntry.getKey();
                    // if this version is already recovered, don't re-evaluate it again
                    if (successfullyRecoveredVersions.get(secretId).contains(versionNumber)) {
                        continue;
                    }
                    if (versionEntry.getValue().size() >= LibState.getInstance().getMinNumberOfHelpersForRecovery()) {
                        recoverableVersions.put(versionNumber, recoverableShares.get(secretId).get(versionNumber));
                    }
                }
            }
            return(recoverableVersions);
    }

    public void evaluateAndSendGetShareRequests(DeRecSecret.Id secretId) {
        HashMap<Integer, ArrayList<DeRecHelperStatus>> sendMap = evaluate(secretId);
        if (!sendMap.isEmpty()) {
            System.out.println("*********  in evaluateAndSendGetShareRequests sendMap is present *********");
        }
        for (HashMap.Entry<Integer, ArrayList<DeRecHelperStatus>> sendEntry : sendMap.entrySet()) {
            int versionNumber = sendEntry.getKey();
            ArrayList<DeRecHelperStatus> toList = sendEntry.getValue();

            System.out.println("---------------------------------------------In evaluateAndSendGetShareRequests: For " +
                    "version: " + versionNumber + " toList size: " + toList.size());
            for (DeRecHelperStatus helperToSend: toList) {
                System.out.println("HelperToSend: " + helperToSend + ", name: " + helperToSend.getId().getName());
            }
            System.out.println("And getShareRequestsSent size is: " + getShareRequestsSent.get(secretId).get(versionNumber).size());
            for (var hs : getShareRequestsSent.get(secretId).get(versionNumber)) {
                System.out.println("hs: " + hs + ", name: " + hs.getId().getName());
            }
            System.out.println("----");


            for (DeRecHelperStatus helperToSend: toList) {

                if (!getShareRequestsSent.get(secretId).get(versionNumber).contains(helperToSend)) {
                    // Remember that we sent this request out, so we don't re-send this request multiple times
                    // Ideally, this should be done *after* we send the message. But for testing when we run the
                    // timer every 1 second, there are situations when the httpClient doesn't send a request in 1
                    // second and that results in sending multiple requests to the same helper.
                    getShareRequestsSent.get(secretId).get(versionNumber).add(helperToSend);

                    // send GetShare message
                    GetShareMessages.sendGetShareRequestMessage(
                            LibState.getInstance().getMeSharer().getMyLibId().getMyId(), helperToSend.getId(),
                            secretId, LibState.getInstance().getMeHelper().getMyLibId().getPublicEncryptionKeyId(),
                            versionNumber);
                    System.out.println("Sent sendGetShareRequestMessage to " + helperToSend + ", name: " + helperToSend.getId().getName());

                }
            }

            System.out.println("After processing - In evaluateAndSendGetShareRequests");
            System.out.println("And getShareRequestsSent size is: " + getShareRequestsSent.get(secretId).get(versionNumber).size());
            for (var hs : getShareRequestsSent.get(secretId).get(versionNumber)) {
                System.out.println("hs: " + hs + ", name: " + hs.getId().getName());
            }
            System.out.println("----");

        }
    }

    public void versionRecovered(DeRecSecret.Id secretId, int versionNumber) {
        successfullyRecoveredVersions.get(secretId).add(versionNumber);
    }


    public boolean saveRetrievedCommittedDeRecShare(DeRecSecret.Id secretId, Integer versionNumber,
                                                    DeRecHelperStatus helperStatus,
                                                CommittedDeRecShare committedDeRecShare) {
        System.out.println("In saveRetrievedCommittedDeRecShare for version # " + versionNumber);
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
            System.out.println("Attempting to recombine");
            // Find out the current secret (in the context of the recovering user) so that we can populate the
            // version and helpers into that.
            var currentSecret = (SecretImpl) LibState.getInstance().getMeSharer().getSecret(secretId);

            // If the secret has already recovered a version, then only allow newer versions to recover
            if (!currentSecret.isRecovering()) {
                if (versionNumber <= currentSecret.getMaxVersionNumber()) {
                    System.out.println("VersionImpl " + versionNumber + "is lesser than current version of " + currentSecret.getMaxVersionNumber());
                    return false;
                }
            }

            DummyMerkledVssFactory merkledVss = new DummyMerkledVssFactory();
            System.out.println("created merkledVss");
            System.out.println("Dump 1" + toString());
            // TODO Check the merkle paths and uniqueness of the committment here
            byte[] encryptedValueToProtect = merkledVss.combine(secretId.getBytes(), versionNumber,
                    retrievedCommittedDeRecShares.get(secretId).get(versionNumber).values().stream()
                            .map(cds -> cds.getDeRecShare().getEncryptedSecret()).toList());
            if (encryptedValueToProtect == null || encryptedValueToProtect.length == 0) {
                System.out.println("Combine sent no data");
                return false;
            }
            System.out.println("created encryptedValueToProtect successfully, len: " + encryptedValueToProtect.length);

            // Now that we have successfully recombined, remove the shares from retrievedCommittedDeRecShares
            retrievedCommittedDeRecShares.get(secretId).put(versionNumber, new HashMap<>());

            // TODO: How will this even work? This was encrypted using the publicKey that the sharer had in the previous
            //  life.
            byte[] serializedSecretMessage = dummyDecryptSecret(encryptedValueToProtect);


            System.out.println("After dummyDecryptSecret size: " + serializedSecretMessage.length);
            SecretImpl recoveredSecret = parseSecretMessage(secretId, serializedSecretMessage);
            System.out.println("######################################");
            System.out.println("RECOVERY DONE for version: " + versionNumber);
            System.out.println("######################################");
            System.out.println("Recovered description " + recoveredSecret.getDescription());
            System.out.println("Recovered versions size " + recoveredSecret.getVersions().size());

            // Add Versions to the currentSecret
            for ( HashMap.Entry<Integer, ? extends DeRecVersion> entry : recoveredSecret.getVersions().entrySet()) {
                VersionImpl version = (VersionImpl) entry.getValue();

                int vNumber = entry.getKey();
                if (vNumber != versionNumber) {
                    System.out.println("******************* ERROR: there's a mismatch of versions in " +
                            "attemptToRecombine - called with " + versionNumber + ", but recoveredVersion is " + vNumber);
                } else {
                    System.out.println("version numberss match");
                }
                System.out.println("Recovered version text: " + new String(version.getProtectedValue()));
                System.out.println(version.getSecret().equals(currentSecret) ? "*****VersionImpl has different " +
                        "secret*****" :
                        "*****VersionImpl's secret matches currentSecret*****");
//                currentSecret.addVersion(versionNumber, version);
                currentSecret.updateAsync(versionNumber, version.getProtectedValue());
                System.out.println("Added version to currentSecret");
                System.out.printf("Check: " +  new String(currentSecret.getVersionByNumber(versionNumber).getProtectedValue()));
            }

//            System.out.println("Going to Add helperStatuses to the currentSecret");
//            // Add helperStatuses to the currentSecret
//            for (DeRecHelperStatus helperStatus : (List<DeRecHelperStatus>)recoveredSecret.getHelperStatuses()) {
//                System.out.println("Processing helperstatus: " + helperStatus.getId().getName());
//                // Add this helperStatus to the currentSecret only if it doesn't already exist.
//                Optional<? extends DeRecHelperStatus> existingHelperStatusOptional =
//                        currentSecret.getHelperStatuses().stream()
//                        .filter(hs -> hs.getId().getPublicEncryptionKey().equals(helperStatus.getId().getPublicEncryptionKey()))
//                        .findFirst();
//                System.out.println("After findfirst");
//                if (!existingHelperStatusOptional.isPresent()) {
//                    System.out.println("New helper found!!! " + helperStatus.getId().getName());
////                    currentSecret.addHelpersAsync(new ArrayList<>(Arrays.asList(helperStatus.getId())));
////                    currentSecret.processAddHelpersAsync(new ArrayList<>(Arrays.asList(helperStatus.getId())), false);
//                    currentSecret.addRecoveredHelper((HelperStatusImpl) helperStatus);
//                    System.out.println("Added Helper successfully");
//                    System.out.println("Check2: " + currentSecret.getHelperStatuses().contains(helperStatus));
//                } else {
//                    System.out.println("Helper " + helperStatus.getId().getName() + " is already present in the " +
//                            "currentSecret");
//                }
//
//            }

            System.out.println("Going to Add helperStatuses to the currentSecret");
            // Add helperStatuses to the currentSecret
            for (DeRecHelperStatus helperStatus : (List<DeRecHelperStatus>)recoveredSecret.getHelperStatuses()) {
                System.out.println("Processing helperstatus: " + helperStatus.getId().getName());
                // Add this helperStatus to the currentSecret only if it doesn't already exist.
//                Optional<? extends DeRecHelperStatus> existingHelperStatusOptional =
//                        currentSecret.getHelperStatuses().stream()
//                                .filter(hs -> hs.getId().getPublicEncryptionKey().equals(helperStatus.getId().getPublicEncryptionKey()))
//                                .findFirst();
//                System.out.println("After findfirst");
//                if (!existingHelperStatusOptional.isPresent()) {
                    System.out.println("New helper found!!! " + helperStatus.getId().getName());
                    currentSecret.clearOneHelper(helperStatus.getId());
                System.out.println("Removed " + helperStatus.getId().getName() + " before adding as recovered helper");
                currentSecret.addRecoveredHelper((HelperStatusImpl) helperStatus);
                    System.out.println("Added Helper successfully");
                    System.out.println("Check2: " + currentSecret.getHelperStatuses().contains(helperStatus));

                    // Restore Sharer's LibIdentity
                LibState.getInstance().setMyHelperAndSharerId(LibState.getInstance().getMeSharer().getMyLibId());
//                } else {
//                    System.out.println("Helper " + helperStatus.getId().getName() + " is already present in the " +
//                            "currentSecret");
//                }

            }
            // Declare that this secret has recovered!
            currentSecret.setRecovering(false);

            // Recalculate the shares for all versions now
            for (DeRecVersion deRecVersion: currentSecret.getVersions().values().stream().toList()) {
                VersionImpl version = (VersionImpl) deRecVersion;
                version.createShares();
            }


            System.out.println("--- really done---");
            return true;
        } catch (Exception ex) {
            System.out.println("Exception in attemptToRecombine");
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

        for (Map.Entry<DeRecSecret.Id, HashMap<Integer, HashMap<DeRecHelperStatus, CommittedDeRecShare>>> secretEntry :
                retrievedCommittedDeRecShares.entrySet()) {
            sb.append("Secret Id: ").append(secretEntry.getKey().toString()).append("\n");

            for (Map.Entry<Integer, HashMap<DeRecHelperStatus, CommittedDeRecShare>> versionEntry : secretEntry.getValue().entrySet()) {
                sb.append("  VersionImpl Number: ").append(versionEntry.getKey()).append("\n");
                HashMap<DeRecHelperStatus, CommittedDeRecShare> map = versionEntry.getValue();
                for (DeRecHelperStatus helperStatus: map.keySet()) {
                    sb.append("  Helper: ").append(helperStatus.getId().getName()).append(": ");
                    sb.append(" Ver Descr:").append(map.get(helperStatus).getDeRecShare().getVersionDescription());
                    sb.append(" Ver num:").append(map.get(helperStatus).getDeRecShare().getVersion());
                }
            }
        }
        return sb.toString();
    }
}
