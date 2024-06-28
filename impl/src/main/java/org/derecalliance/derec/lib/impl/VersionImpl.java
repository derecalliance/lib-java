package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.api.DeRecVersion;
import org.derecalliance.derec.protobuf.Storeshare;
import org.derecalliance.derec.protobuf.Verify;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

//import static org.derecalliance.derec.lib.CryptoPrimitives.dummyEncryptSecret;
import static org.derecalliance.derec.lib.impl.CryptoPrimitives.dummyEncryptSecret;
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
                // TODO: call Shamir Secret logic to split shares. For now, let's return the actual message itself
                var myStatus = new SharerStatusImpl(LibState.getInstance().getMeSharer().getMyLibId().getMyId());
                Storeshare.Secret secretMsg = secret.createSecretMessage(versionNumber);
                byte[] valueToProtect = secretMsg.toByteArray();

                logger.debug("Creating shares for version " + versionNumber);
                List<byte[]> committedDeRecSharesList = LibState.getInstance().getDerecCryptoImpl().share(secret.getSecretId().getBytes(), versionNumber, valueToProtect, numPairedHelpers,
                        (int)Math.ceil((double) numPairedHelpers / 2));
                logger.debug("created " + committedDeRecSharesList.size() + " shares for version " + versionNumber + ", numPairedHelpers is " + numPairedHelpers);

                for (int i = 0; i < numPairedHelpers; i++) {
                    Storeshare.CommittedDeRecShare cds = Storeshare.CommittedDeRecShare.parseFrom(committedDeRecSharesList.get(i));
                    Storeshare.DeRecShare drs =  Storeshare.DeRecShare.parseFrom(cds.getDeRecShare());
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
            logger.error("Exception in createShares");
            ex.printStackTrace();
        }
    }

    void sendSharesToPairedHelpers() {
        logger.debug("in sendSharesToPairedHelpers - isPRotected=" + isProtected());
        if (sharesMap.isEmpty()) {
            createShares();
        } else {
            logger.debug("Sharesmap is not empty - not creating");
        }
        for ( HashMap.Entry<DeRecHelperStatus, ShareImpl>entry : sharesMap.entrySet()) {
            ShareImpl share = entry.getValue();
            if (!share.isConfirmed()) {
                logger.debug("************************************************ ************ *Sending share to " + entry.getKey().getId().getName());

                StoreShareMessages.sendStoreShareRequestMessage(
                        LibState.getInstance().getMeSharer().getMyLibId().getMyId(),
                        entry.getKey().getId(),
                        secret.getSecretId(),
                        LibState.getInstance().getMeSharer().getMyLibId().getPublicEncryptionKeyId(),
                        share);
            } else {
                logger.debug("ShareImpl is already confirmed");
            }
        }
    }


    void sendVerificationRequestsToPairedHelpers() {
        logger.info("In sendVerificationRequestsToPairedHelpers");

        // helper paired
        // helper refused -> dont recalc
        // helper failed -> recalculate
        //
        // if helper doesnt respond for 20 seconds -> refused.
        //  dont recalculate shares and keep sending verifications
        //

        //

        for ( HashMap.Entry<DeRecHelperStatus, ShareImpl>entry : sharesMap.entrySet()) {

            long rand = new Random().nextLong();
            byte[] nonce = ByteBuffer.allocate(8).putLong(rand).array();

            ShareImpl share = entry.getValue();
            VerifyShareMessages.sendVerifyShareRequestMessage(
                    LibState.getInstance().getMeSharer().getMyLibId().getMyId(),
                    entry.getKey().getId(),
                    secret.getSecretId(),
                    LibState.getInstance().getMeSharer().getMyLibId().getPublicEncryptionKeyId(),
                    versionNumber,nonce);
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

            // while unresponded count >20 and <60, keep sending verification req to that helper
            // helper responds within that time
            //  change status to paired
            // helper doesnt respond within that time
            //  change status to failed and recalculate shares
            // 30
            // if unresponded count > 60: mark failed and recalculate
            // else if unresponded count > 20: mark refused

        }
    }

    public void updateConfirmationShareStorage(DeRecHelperStatus helperStatus, boolean status) {
        ShareImpl share = sharesMap.get(helperStatus);
        share.updateConfirmation(status);
        secret.updateKeepListIfNeeded();
    }
    public ShareImpl getShare(DeRecHelperStatus helperStatus) {
        return sharesMap.get(helperStatus);
    }

    public boolean handleVerificationResponse(DeRecIdentity helperId, byte[] messageNonce, byte[] messageHash,
                                           int messageVersionNumber) {
        Optional<? extends DeRecHelperStatus> helperStatusOptional =
                secret.getHelperStatuses().stream().filter(hs -> hs.getId().equalsKey(helperId)).findFirst();
                if (!helperStatusOptional.isPresent()) {
                    logger.debug("Could not find helper status for sender: " + helperId.getName());
                    return false;
                }

                DeRecHelperStatus helperStatus = helperStatusOptional.get();

//                if (helperStatus == null) {
//                    logger.debug("Could not find helper status for sender: " + helperId.getName());
//                    return;
//                } else {
                    ShareImpl share = getShare(helperStatus);
                    if (share == null) {
                        // The share can be null if we had previously sent a verification request to a helper
                        // that we later removed or declared inactive before they could respond.
                        return false;
                    }
                    byte [] expectedHash = calculateVerificationHash(share.getCommittedDeRecShare().toByteArray(), messageNonce);
                    logger.debug("Expected hash: V(" + versionNumber + ") " + Base64.getEncoder().encodeToString(expectedHash));
                    logger.debug("Received hash: V(" + messageVersionNumber + ") " + Base64.getEncoder().encodeToString(messageHash));
                    if (Arrays.equals(expectedHash, messageHash)) {
                        // Re-verify that this share is still confirmed
                        updateConfirmationShareStorage(helperStatus, true);
                        logger.debug("hashes matched");
                        unsuccessfulVerificationRequests.put(helperStatus, 0);
                        if (helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.REFUSED) {
                            ((HelperStatusImpl) helperStatus).setStatus(DeRecPairingStatus.PairingStatus.PAIRED);
//                            createShares();
                        }
                        ((HelperStatusImpl) helperStatus).setLastVerificationTime(Instant.now());
                        return true;
                    } else {
                        updateConfirmationShareStorage(helperStatus, false);
                        logger.debug("hashes not matched");
                        return false;
                    }
//                }
    }

//    private void writeObject(ObjectOutputStream out) throws IOException {
//        out.writeInt(versionNumber);
//        out.writeObject(protectedValue);
//        out.writeBoolean(isProtected);
//    }
//
//    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
//        versionNumber = in.readInt();
//        protectedValue = (byte[]) in.readObject();
//        isProtected = in.readBoolean();
//    }
}
