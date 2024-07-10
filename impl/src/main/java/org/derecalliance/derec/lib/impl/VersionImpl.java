package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.api.DeRecVersion;
import org.derecalliance.derec.protobuf.Storeshare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static org.derecalliance.derec.lib.impl.VerifyShareMessages.calculateVerificationHash;

public class VersionImpl implements DeRecVersion {
    SecretImpl secret;
    int versionNumber;
    byte[] protectedValue;
    boolean isProtectedStatus;
    HashMap<DeRecHelperStatus, ShareImpl> sharesMap;
    HashMap<DeRecHelperStatus, Integer> unsuccessfulVerificationRequests;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public VersionImpl(SecretImpl secret, byte[] protectedValue, int versionNumber) {
        this.secret = secret;
        this.protectedValue = protectedValue;
        this.versionNumber = versionNumber;
        this.sharesMap = new HashMap<>();
        unsuccessfulVerificationRequests = new HashMap<>();
        this.isProtectedStatus = false;
    }

    public VersionImpl(SecretImpl secret, byte[] protectedValue) {
        this(secret, protectedValue, 1);
    }

    @Override
    public DeRecSecret getSecret() {
        return (DeRecSecret) secret;
    }

    @Override
    public int getVersionNumber() {
        return versionNumber;
    }

    @Override
    public byte[] getProtectedValue() {
        return protectedValue;
    }

    @Override
    public boolean isProtected() {
        calculateIsProtectedStatus();
        return isProtectedStatus;
    }

    /**
     * Check whether this version is protected (i.e. enough Helpers have
     * 1) been sent a share of this version, and
     * 2) enough Helpers have confirmed storage of this version in the VerifyShareResponse.
     * Updates the isProtectedStatus class variable based on the above conditions.
     */
    void calculateIsProtectedStatus() {
        long protectedCount = sharesMap.values().stream()
                .filter(obj -> obj.isConfirmed() == true)
                .count();
        if (protectedCount >= (sharesMap.size() * LibState.getInstance().getMinPercentOfSharesForConfirmation()) &&
                sharesMap.size() >= LibState.getInstance().getMinNumberOfHelpersForSendingShares()) {
            isProtectedStatus = true;
        } else {
            isProtectedStatus = false;
        }
    }

    public String debugStr() {
        String str = "VersionImpl: " + versionNumber + ", Value: " +
                new String(protectedValue, StandardCharsets.UTF_8) + "\n";
        return str;
    }

    /**
     * Creates shares for this version based on how many paired Helpers the Sharer has. Calls the crypto library's
     * split() method to cryptographically create shares based on Shamir's secret sharing algorithm.
     */
    public void createShares() {
        try {


            // Find the list of healthy helpers (Paired helpers)
            List<DeRecHelperStatus> filteredList = (List<DeRecHelperStatus>) secret.getHelperStatuses().stream()
                    .filter(helperStatus -> helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.PAIRED)
                    .collect(Collectors.toList());
            logger.debug("FilteredList size: " + filteredList.size() + ", numHelpers; " + secret.getHelperStatuses().size());
            for (DeRecHelperStatus hs : filteredList) {
                logger.debug(hs.toString());
            }
            ArrayList<DeRecHelperStatus> pairedHelpers = new ArrayList<>(filteredList);
            int numPairedHelpers = pairedHelpers.size();

            // Create shares
            sharesMap.clear();
            if (numPairedHelpers >= LibState.getInstance().getMinNumberOfHelpersForSendingShares()) {
                var myStatus = new SharerStatusImpl(secret.getLibId().getMyId());
                Storeshare.Secret secretMsg = secret.createSecretMessage(versionNumber);
                byte[] valueToProtect = secretMsg.toByteArray();

                logger.debug("Creating shares for version " + versionNumber);
                List<byte[]> committedDeRecSharesList = LibState.getInstance().getDerecCryptoImpl().share(secret.getSecretId().getBytes(), versionNumber, valueToProtect, numPairedHelpers,
                        (int) Math.max((double) numPairedHelpers / 2, LibState.getInstance().getMinNumberOfHelpersForRecovery()));
                logger.debug("created " + committedDeRecSharesList.size() + " shares for version " + versionNumber + ", numPairedHelpers is " + numPairedHelpers);

                for (int i = 0; i < numPairedHelpers; i++) {
                    Storeshare.CommittedDeRecShare cds = Storeshare.CommittedDeRecShare.parseFrom(committedDeRecSharesList.get(i));
                    Storeshare.DeRecShare drs = Storeshare.DeRecShare.parseFrom(cds.getDeRecShare());
                    logger.debug("x value ->" + Base64.getEncoder().encodeToString(drs.getX().toByteArray()));
                    logger.debug("secret id ->" + Base64.getEncoder().encodeToString(drs.getSecretId().toByteArray()) + ", version number -> " + drs.getVersion());
                    ShareImpl share = new ShareImpl(this.secret.getSecretId(), versionNumber, myStatus, cds);
                    sharesMap.put(pairedHelpers.get(i), share);
                    if (!unsuccessfulVerificationRequests.containsKey(pairedHelpers.get(i))) {
                        unsuccessfulVerificationRequests.put(pairedHelpers.get(i), 0);
                    }

                }
            }
            logger.debug("Created shares. Sharesmap size: " + sharesMap.size());
        } catch (Exception ex) {
            logger.error("Exception in createShares", ex);
        }
    }

    /**
     * Sends StoreShareRequest message to all paired Helpers.
     */
    void sendSharesToPairedHelpers() {
        logger.debug("in sendSharesToPairedHelpers - isPRotected=" + isProtected());
        if (sharesMap.isEmpty()) {
            createShares();
        } else {
            logger.debug("Sharesmap is not empty - not creating");
        }
        for (HashMap.Entry<DeRecHelperStatus, ShareImpl> entry : sharesMap.entrySet()) {
            ShareImpl share = entry.getValue();
            if (!share.isConfirmed()) {
                logger.debug("************************************************ ************ *Sending share to " + entry.getKey().getId().getName());

                StoreShareMessages.sendStoreShareRequestMessage(
                        secret.getLibId().getMyId(),
                        entry.getKey().getId(),
                        secret.getSecretId(),
                        secret.getLibId().getPublicEncryptionKeyId(),
                        share);
            } else {
                logger.debug("ShareImpl is already confirmed");
            }
        }
    }


    /**
     * Sends VerifyShareMessage to all paired Helpers. Updates the pairing status of a Helper based on their
     * responsiveness.
     */
    void sendVerificationRequestsToPairedHelpers() {
        logger.info("In sendVerificationRequestsToPairedHelpers");
        for (HashMap.Entry<DeRecHelperStatus, ShareImpl> entry : sharesMap.entrySet()) {

            long rand = new Random().nextLong();
            byte[] nonce = ByteBuffer.allocate(8).putLong(rand).array();

            ShareImpl share = entry.getValue();
            VerifyShareMessages.sendVerifyShareRequestMessage(
                    secret.getLibId().getMyId(),
                    entry.getKey().getId(),
                    secret.getSecretId(),
                    secret.getLibId().getPublicEncryptionKeyId(),
                    versionNumber, nonce);
            logger.debug("Sent VerifyShareRequestMessage to " + entry.getKey().getId().getName());
            // Every time we send a verification request, increment the unsuccessful verification count by 1.
            unsuccessfulVerificationRequests.put(entry.getKey(),
                    unsuccessfulVerificationRequests.get(entry.getKey()) + 1);
            logger.info("Incremented unsuccessfulVerificationRequests by 1 for " + entry.getKey().getId().getName());

            if (unsuccessfulVerificationRequests.get(entry.getKey()) > LibState.getInstance().thresholdToMarkHelperFailed) {
                // If the number of unanswered/failed verification requests is greater than
                // thresholdToMarkHelperFailed, set the helper status to FAILED, and recalculate shares.
                if (entry.getKey().getStatus() == DeRecPairingStatus.PairingStatus.REFUSED) {
                    ((HelperStatusImpl) entry.getKey()).setStatus(DeRecPairingStatus.PairingStatus.FAILED);
                    secret.helperStatusChanged();
                }
                createShares();
                logger.debug("HELPER FAILED VERIFICATION");
            } else if (unsuccessfulVerificationRequests.get(entry.getKey()) > LibState.getInstance().thresholdToMarkHelperRefused) {
                // If the number of unanswered/failed verification requests is greater than thresholdToMarkHelperRefused, set that helper's pairing
                // status to REFUSED. We hope that the helper can come back.
                if (entry.getKey().getStatus() == DeRecPairingStatus.PairingStatus.PAIRED) {
                    ((HelperStatusImpl) entry.getKey()).setStatus(DeRecPairingStatus.PairingStatus.REFUSED);
                }
                // createShares(); we don't recreate shares here
                logger.debug("HELPER REFUSED VERIFICATION");
            }
        }
    }

    /**
     * Updates whether a Helper has confirmed storage of a share.
     *
     * @param helperStatus Helper whom the share was sent to
     * @param status       Whether the share was confirmed by the Helper
     */
    public void updateConfirmationShareStorage(DeRecHelperStatus helperStatus, boolean status) {
        ShareImpl share = sharesMap.get(helperStatus);
        share.updateConfirmation(status);
        secret.updateKeepListIfNeeded();
    }

    /**
     * Gets the share sent to a Helper.
     *
     * @param helperStatus Helper whom the share was sent to
     * @return The share stored with a given Helper
     */
    public ShareImpl getShare(DeRecHelperStatus helperStatus) {
        return sharesMap.get(helperStatus);
    }

    /**
     * Handles a VerifyShareResponseMessage from a Helper - checks that the expected messageHash is correct and updates
     * confirmation of the share and pairing status of the Helper accordingly.
     *
     * @param helperId             DeRecIdentity of the Helper who sent the VerifyShareResponseMessage
     * @param messageNonce         Challenge nonce associated with the message
     * @param messageHash          Hash of the CommittedDeRecShare + nonce
     * @param messageVersionNumber Version of the secret being verified
     * @return true if the response is as expected, false for all other cases
     */
    public boolean handleVerificationResponse(DeRecIdentity helperId, byte[] messageNonce, byte[] messageHash,
                                              int messageVersionNumber) {
        Optional<? extends DeRecHelperStatus> helperStatusOptional =
                secret.getHelperStatuses().stream().filter(hs -> hs.getId().equalsKey(helperId)).findFirst();
        if (!helperStatusOptional.isPresent()) {
            logger.debug("Could not find helper status for sender: " + helperId.getName());
            return false;
        }

        DeRecHelperStatus helperStatus = helperStatusOptional.get();
        ShareImpl share = getShare(helperStatus);
        if (share == null) {
            // The share can be null if we had previously sent a verification request to a helper
            // that we later removed or declared inactive before they could respond.
            return false;
        }
        byte[] expectedHash = calculateVerificationHash(share.getCommittedDeRecShare().toByteArray(), messageNonce);
        logger.debug("Expected hash: V(" + versionNumber + ") " + Base64.getEncoder().encodeToString(expectedHash));
        logger.debug("Received hash: V(" + messageVersionNumber + ") " + Base64.getEncoder().encodeToString(messageHash));
        if (Arrays.equals(expectedHash, messageHash)) {
            // Re-verify that this share is still confirmed
            updateConfirmationShareStorage(helperStatus, true);
            logger.debug("hashes matched");
            unsuccessfulVerificationRequests.put(helperStatus, 0);
            if (helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.REFUSED) {
                ((HelperStatusImpl) helperStatus).setStatus(DeRecPairingStatus.PairingStatus.PAIRED);
            }
            ((HelperStatusImpl) helperStatus).setLastVerificationTime(Instant.now());
            return true;
        } else {
            updateConfirmationShareStorage(helperStatus, false);
            logger.debug("hashes not matched");
            return false;
        }
    }
}
