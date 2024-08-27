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

import com.google.protobuf.ByteString;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Parameterrange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HelperImpl implements DeRecHelper {
    LibIdentity myLibId;
    CopyOnWriteArrayList<Long> generatedNonces = new CopyOnWriteArrayList<>();
    Parameterrange.ParameterRange parameterRange;
    boolean paused = false;
    ConcurrentHashMap<DeRecIdentity, ConcurrentHashMap<DeRecSecret.Id, SharerStatusImpl>> sharerStatuses =
            new ConcurrentHashMap<>();

    // During recovery, the sharer will come back with a new public key. To help this sharer recover their
    // previously stored shares, the helper must map the recovering sharer's public key to their previous lost
    // identity that they were helping.
    // Maps the public key of the recovering helper to their previous DeRecIdentity
    public HashMap<String, List<SharerStatusImpl>> publicKeyToLostSharerMap = new HashMap<>();

    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private Function<DeRecHelper.Notification, DeRecHelper.NotificationResponse> listener = n -> {
        return null;
    }; // do nothing

    // Map of shares being stored by this Helper
    private final ConcurrentHashMap<String, ConcurrentHashMap<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>>>
            recdCommittedDeRecShares;

    public class Notification implements DeRecHelper.Notification {
        DeRecHelper.Notification.Type type;
        DeRecIdentity sharerId;
        DeRecSecret.Id secretId;
        int versionNumber;

        public Notification(
                DeRecHelper.Notification.Type type,
                DeRecIdentity sharerId,
                DeRecSecret.Id secretId,
                int versionNumber) {
            this.type = type;
            this.sharerId = sharerId;
            this.secretId = secretId;
            this.versionNumber = versionNumber;
        }

        public DeRecHelper.Notification.Type getType() {
            return type;
        }

        public DeRecIdentity getSharerId() {
            return sharerId;
        }

        public DeRecSecret.Id getSecretId() {
            return secretId;
        }

        public int getVersion() {
            return versionNumber;
        }
    }

    public class NotificationResponse implements DeRecHelper.NotificationResponse {
        String reason;
        boolean result; // true if OK to proceed, false if application denies request
        Object referenceObject; // reference object, return null if not needed

        public NotificationResponse(boolean result, String reason, Object referenceObject) {
            this.result = result;
            this.reason = reason;
            this.referenceObject = referenceObject;
        }

        @Override
        public boolean getUnpairPlease() {
            return false;
        }

        @Override
        public String getReason() {
            return reason;
        }

        @Override
        public boolean getResult() {
            return result;
        }

        @Override
        public Object getReferenceObject() {
            return referenceObject;
        }
    }

    public HelperImpl(String name, String contact, String address) {
        recdCommittedDeRecShares = new ConcurrentHashMap<>();
        myLibId = new LibIdentity(name, contact, address);
        parameterRange = Parameterrange.ParameterRange.newBuilder().build();

        // Register in the messageHashAndSecretIdToIdentityMap table for self id.
        // Since we are a helper, we don't have a secret id, hence register with a null secret id
        logger.debug("Adding myself (Helper) " + name + " to messageHashAndSecretIdToIdentityMap");
        LibState.getInstance()
                .registerMessageHashAndSecretIdToIdentity(
                        ByteString.copyFrom(myLibId.getMyId().getPublicEncryptionKeyDigest()), null, myLibId.getMyId());
        logger.debug("Adding myself (Helper) " + name + " to publicKeyToIdentityMap");
        LibState.getInstance().registerPublicKeyId(myLibId.getPublicEncryptionKeyId(), myLibId);

        LibState.getInstance().setMeHelper(this);
        LibState.getInstance().init(contact, address);
    }

    @Override
    public DeRecHelper.Notification newNotification(
            DeRecHelper.Notification.Type type, DeRecIdentity sharerId, DeRecSecret.Id secretId, int versionNumber) {
        return new Notification(type, sharerId, secretId, versionNumber);
    }

    @Override
    public DeRecHelper.NotificationResponse newNotificationResponse(boolean result, String reason, Object obj) {
        return new NotificationResponse(result, reason, obj);
    }

    @Override
    public String getPublicEncryptionKey() {
        return myLibId.getEncryptionPublicKey();
    }

    @Override
    public int getPublicEncryptionKeyId() {
        return myLibId.getPublicEncryptionKeyId();
    }

    @Override
    public String getPublicSignatureKey() {
        return myLibId.getSignaturePublicKey();
    }

    @Override
    public String getPrivateEncryptionKey() {
        return myLibId.getEncryptionPrivateKey();
    }

    @Override
    public String getPrivateSignatureKey() {
        return myLibId.getSignaturePrivateKey();
    }

    @Override
    public List<? extends ShareImpl> getShares() {
        return recdCommittedDeRecShares.values().stream() // Stream of Map<DeRecSecret.Id, Map<Integer, ShareImpl>>
                .flatMap(secretMap -> secretMap.values().stream()) // Stream of Map<Integer, ShareImpl>
                .flatMap(versionMap -> versionMap.values().stream()) // Stream of ShareImpl
                .collect(Collectors.toList());
    }

    @Override
    public void removeSharer(SharerStatus sharerStatus) {
        // This removes all SharerStatuses for all secretIds for the given sharerStatus
        sharerStatuses.remove(sharerStatus.getId());
    }

    /**
     * Removes a sharer and removes all shares stored for them
     *
     * @param sharerId DeRecIdentity of the sharer to be removed
     * @param secretId SecretId to remove
     * @return
     */
    public boolean removeSharer(DeRecIdentity sharerId, DeRecSecret.Id secretId) {
        SharerStatusImpl sharerStatus = getSharerStatus(sharerId, secretId);

        // Remove from sharerStatuses
        ConcurrentHashMap<DeRecSecret.Id, SharerStatusImpl> secretIdsForSharer =
                sharerStatuses.get(sharerStatus.getId());
        int numSecretIds = secretIdsForSharer.keySet().size();
        if (numSecretIds == 0 || !secretIdsForSharer.containsKey(secretId)) {
            return false;
        } else {
            secretIdsForSharer.remove(secretId);
            if (secretIdsForSharer.keySet().isEmpty()) {
                sharerStatuses.remove(sharerStatus.getId());
            }
        }

        // Remove stored shares
        if (recdCommittedDeRecShares.containsKey(sharerId.getPublicEncryptionKey())) {
            recdCommittedDeRecShares.get(sharerId.getPublicEncryptionKey()).remove(secretId);
            if (recdCommittedDeRecShares
                    .get(sharerId.getPublicEncryptionKey())
                    .keySet()
                    .isEmpty()) {
                recdCommittedDeRecShares.remove(sharerId.getPublicEncryptionKey());
            }
        } else {
            logger.debug("In removeSharer, could not find shares for " + sharerId.getName());
            return false;
        }
        return true;
    }

    @Override
    public List<? extends SharerStatusImpl> getSharers() {
        List<SharerStatusImpl> allSharerStatuses = sharerStatuses.values().stream()
                .flatMap(innerMap -> innerMap.values().stream())
                .collect(ArrayList::new, List::add, List::addAll);

        return allSharerStatuses;
    }

    @Override
    public void removeSecret(SharerStatus sharerStatus, DeRecSecret.Id secretId) {
        ConcurrentHashMap<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>> secretMaps =
                recdCommittedDeRecShares.get(sharerStatus.getId().getPublicEncryptionKey());
        if (secretMaps != null) {
            secretMaps.remove(secretId);
        }
    }

    @Override
    public void removeVersion(SharerStatus sharerStatus, DeRecSecret.Id secretId, int versionNumber) {
        logger.debug("in LIb: removeVersion");
        logger.debug("Before removing version: recdCommittedDeRecShares are: " + sharesToString());
        ConcurrentHashMap<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>> secretMaps =
                recdCommittedDeRecShares.get(sharerStatus.getId().getPublicEncryptionKey());
        if (secretMaps != null) {
            ConcurrentHashMap<Integer, ShareImpl> versionMap = secretMaps.get(secretId);
            if (versionMap != null) {
                versionMap.remove(versionNumber);
            }
        }
        logger.debug("After removing version: recdCommittedDeRecShares are: " + sharesToString());
    }

    @Override
    public List<? extends DeRecSecret.Id> getSecretIds(SharerStatus sharerStatus) {
        List<DeRecSecret.Id> secretIds =
                recdCommittedDeRecShares.values().stream() // Stream of Map<DeRecSecret.Id, Map<Integer, ShareImpl>>
                        .flatMap(sharerMap -> sharerMap.keySet().stream()) // Stream of DeRecSecret.Id
                        .collect(Collectors.toList());
        return secretIds;
    }

    @Override
    public List<? extends Integer> getVersionNumbersForASecret(DeRecSecret.Id secretId) {
        return recdCommittedDeRecShares.values().stream() // Stream of Map<DeRecSecret.Id, Map<Integer, ShareImpl>>
                .map(sharerMap -> sharerMap.get(secretId)) // Stream of Map<Integer, ShareImpl>
                .filter(versionMap -> versionMap != null) // Exclude nulls
                .flatMap(versionMap -> versionMap.keySet().stream()) // Stream of Integer (version numbers)
                .collect(Collectors.toList());
    }

    @Override
    public void setListener(Function<DeRecHelper.Notification, DeRecHelper.NotificationResponse> listener) {
        this.listener = listener;
    }

    /**
     * Stores a share for a given sharer
     *
     * @param sharerStatus  Sharer whom the Helper is storing a share for
     * @param secretId      SecretId of the share
     * @param versionNumber Version number of the share
     * @param share         The share
     */
    void addShare(SharerStatusImpl sharerStatus, DeRecSecret.Id secretId, int versionNumber, ShareImpl share) {
        logger.debug(
                "in addshare, sharer pubEncryptionKey: " + sharerStatus.getId().getPublicEncryptionKey() + "the "
                        + "recdCommittedDeRecShares map is:\n" + sharesToString());

        ConcurrentHashMap<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>> secretMaps =
                recdCommittedDeRecShares.get(sharerStatus.getId().getPublicEncryptionKey());
        if (secretMaps != null) {
            ConcurrentHashMap<Integer, ShareImpl> versionMap = secretMaps.get(secretId);
            if (versionMap != null) {
                versionMap.put(versionNumber, share);
            } else {
                // secretId does not exist for the given sharerStatus
                throw new IllegalArgumentException("Secret ID not found for the provided Sharer Status.");
            }
        } else {
            // sharerStatus does not exist
            throw new IllegalArgumentException("Sharer Status not found.");
        }
    }

    ShareImpl getShare(DeRecIdentity sharerId, DeRecSecret.Id secretId, int versionNumber) {
        return recdCommittedDeRecShares
                .getOrDefault(sharerId.getPublicEncryptionKey(), new ConcurrentHashMap<>())
                .getOrDefault(secretId, new ConcurrentHashMap<>())
                .get(versionNumber);
    }

    Parameterrange.ParameterRange getParameterRange() {
        return parameterRange;
    }

    /**
     * Adds a new sharer (identified by SharerStatusImpl) for which this helper will start storing data
     *
     * @param sharerStatus
     */
    void addSharer(SharerStatusImpl sharerStatus, DeRecSecret.Id secretId) {
        if (!sharerStatuses.containsKey(sharerStatus.getId())) {
            sharerStatuses.put(sharerStatus.getId(), new ConcurrentHashMap<>());
        }
        sharerStatuses.get(sharerStatus.getId()).put(secretId, sharerStatus);

        if (recdCommittedDeRecShares.get(sharerStatus.getId().getPublicEncryptionKey()) == null) {
            recdCommittedDeRecShares.put(sharerStatus.getId().getPublicEncryptionKey(), new ConcurrentHashMap<>());
            logger.debug("-------- added sharer to recdCommittedDeRecShares map ------------------------");
        }
        logger.debug("in addsharer, the recdCommittedDeRecShares map is:\n" + sharesToString());
    }

    SharerStatusImpl getSharerStatus(DeRecIdentity sharerId, DeRecSecret.Id secretId) {
        return sharerStatuses.get(sharerId).get(secretId);
    }

    /**
     * Adds a new secret for a sharer
     *
     * @param sharerStatus Sharer
     * @param secretId     Secret id
     */
    void addSecret(SharerStatusImpl sharerStatus, DeRecSecret.Id secretId) {
        ConcurrentHashMap<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>> smap =
                recdCommittedDeRecShares.get(sharerStatus.getId().getPublicEncryptionKey());
        if (smap == null) {
            logger.debug("Attempting to add secret to non-existent sharer");
            throw new RuntimeException("Attempting to add secret to non-existent sharer");
        }
        if (smap.get(secretId) == null) {
            smap.put(secretId, new ConcurrentHashMap<>());
        }
        logger.debug("in addsecret, the recdCommittedDeRecShares map is:\n" + sharesToString());
    }

    public long createAndStoreNewNonce() {
        long nonce = new Random().nextLong();
        generatedNonces.add(nonce);
        logger.debug("in createAndStoreNewNonce: generated nonces is:" + generatedNonces.toString());
        return nonce;
    }

    public boolean validateAndRemoveNonce(long nonce) {
        // TODO: not sure if we should remove the nonce - what if the
        //  PairingResponse is lost, and the initiator resends the
        //  PairingRequest after a timeout?

        logger.debug("in validateAndRemoveNonce: nonces are:" + generatedNonces.toString());
        return true;
    }

    public boolean validateParameterRange(Parameterrange.ParameterRange parameterRange) {
        return true;
    }

    public LibIdentity getMyLibId() {
        return myLibId;
    }

    /**
     * isPaused() and setPaused() are used only for demo purposes to show a Helper losing connectivity for some time
     */
    public boolean isPaused() {
        return paused;
    }

    public void setPaused(boolean paused) {
        this.paused = paused;
    }

    public String sharesToString() {
        String ret = "";

        // iterate over public key hash (from sharerStatus)
        for (Map.Entry<String, ConcurrentHashMap<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>>>
                pubKeyHashEntry : recdCommittedDeRecShares.entrySet()) {
            String pubKey = pubKeyHashEntry.getKey();
            ret += "Public key (sharer status): " + pubKey + "\n";

            // iterate over the secretid
            for (Map.Entry<DeRecSecret.Id, ConcurrentHashMap<Integer, ShareImpl>> secretEntry :
                    pubKeyHashEntry.getValue().entrySet()) {
                DeRecSecret.Id secretId = secretEntry.getKey();
                ret += "    Secret id: " + secretId + "\n";

                // iterate over the versions
                for (Map.Entry<Integer, ShareImpl> versionEntry :
                        secretEntry.getValue().entrySet()) {
                    Integer versionNumber = versionEntry.getKey();
                    ShareImpl share = versionEntry.getValue();
                    ret += "        version-" + versionNumber + "\n";
                }
            }
        }
        return ret;
    }

    public String sharerStatusesToString() {
        String ret = "Sharer statuses:\n";
        for (DeRecIdentity deRecIdentity : sharerStatuses.keySet()) {
            ret += "Id: " + deRecIdentity.getName() + ", Pub encryption key: " + deRecIdentity.getPublicEncryptionKey()
                    + "\n";
            for (DeRecSecret.Id secretId : sharerStatuses.get(deRecIdentity).keySet()) {
                ret += "    Secret: " + secretId + ", Status: "
                        + sharerStatuses.get(deRecIdentity).get(secretId).getStatus() + "\n";
            }
        }
        ret += "-----\n";
        return ret;
    }

    /**
     * Based on the keepList received in a StoreShareRequestMessage, update the versions stored.
     *
     * @param sharerId DeRecIdentity of the sharer
     * @param secretId SecretId the keepList is for
     * @param keepList The keepList from the StoreShareRequestMessage
     */
    void deleteCommittedDerecSharesBasedOnUpdatedKeepList(
            DeRecIdentity sharerId, DeRecSecret.Id secretId, List<Integer> keepList) {
        // TODO: add logic to not update keepList if the versions in keepList are >= currently stored versions
        logger.debug("In deleteCommittedDerecSharesBasedOnUpdatedKeepList, keeplist is " + keepList);
        // Remove stored shares
        List<Integer> storedVersionNumbersList =
                recdCommittedDeRecShares.get(sharerId.getPublicEncryptionKey()).get(secretId).keySet().stream()
                        .toList();
        storedVersionNumbersList.forEach((storedVersionNumber) -> {
            if (!keepList.contains(storedVersionNumber)) {
                logger.debug("Deleting version " + storedVersionNumber + " since it's not in the keeplist");
                recdCommittedDeRecShares
                        .get(sharerId.getPublicEncryptionKey())
                        .get(secretId)
                        .remove(storedVersionNumber);
            } else {
                logger.debug("Not Deleting version " + storedVersionNumber + " it is in the keeplist");
            }
        });
    }

    /**
     * Reconcile sharer identities after receiving the UI response from the helper
     *
     * @param publicEncryptionKey
     * @param sharerStatuses
     */
    public void registerIdentityReconciliation(String publicEncryptionKey, List<SharerStatusImpl> sharerStatuses) {
        publicKeyToLostSharerMap.put(publicEncryptionKey, sharerStatuses);
    }

    /**
     * Get the previous identities of the Sharer who was recovering
     *
     * @param publicEncryptionKey publicEncryptionKey of the previous sharer
     * @return SharerStatus object
     */
    public List<SharerStatusImpl> getLostSharers(String publicEncryptionKey) {
        return publicKeyToLostSharerMap.get(publicEncryptionKey);
    }

    /**
     * Print routine for publicKeyToLostSharerMap
     */
    public void printPublicKeyToLostSharerMap() {
        logger.debug("printPublicKeyToLostSharerMap");
        for (String key : publicKeyToLostSharerMap.keySet()) {
            logger.debug("New public Key: " + key + " -> " + publicKeyToLostSharerMap.get(key));
        }
        logger.debug("---- End of printPublicKeyToLostSharerMap ----");
    }

    /**
     * Deliver a notification to the UI
     *
     * @param type          Notification type
     * @param sharerId      DeRecIdentity of the Sharer
     * @param secretId      SecretId
     * @param versionNumber Version numeber
     * @return NotificationResponse
     */
    public DeRecHelper.NotificationResponse deliverNotification(
            DeRecHelper.Notification.Type type, DeRecIdentity sharerId, DeRecSecret.Id secretId, int versionNumber) {
        Notification notification = new Notification(type, sharerId, secretId, versionNumber);
        DeRecHelper.NotificationResponse response = listener.apply(notification);
        logger.debug("In deliverNotification: response is " + response);
        return response;
    }
}
