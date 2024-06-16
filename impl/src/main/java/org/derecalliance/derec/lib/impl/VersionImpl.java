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
                sharesMap.size() > LibState.getInstance().getMinNumberOfHelpersForSendingShares()) {
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
            System.out.println("Creating shares for version " + versionNumber);

            // Find the list of healthy helpers (Paired helpers)
            List<DeRecHelperStatus> filteredList = (List<DeRecHelperStatus>) secret.getHelperStatuses().stream()
                    .filter(helperStatus -> helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.PAIRED)
                    .collect(Collectors.toList());
            System.out.println("FilteredList size: " + filteredList.size() + ", numHelpers; " + secret.getHelperStatuses().size());
            for (DeRecHelperStatus hs : filteredList) {
                System.out.println(hs.toString());
            }
            ArrayList<DeRecHelperStatus> pairedHelpers = new ArrayList<>(filteredList);
            int numPairedHelpers = pairedHelpers.size();

            // Create shares
            sharesMap.clear();
            if (numPairedHelpers >= LibState.getInstance().getMinNumberOfHelpersForSendingShares()) {
                // TODO: call Shamir Secret logic to split shares. For now, let's return the actual message itself
                var myStatus =
                        new SharerStatusImpl(LibState.getInstance().getMeSharer().getMyLibId().getMyId());
//                byte[] valueToProtect = secret.serialize();
                Storeshare.Secret secretMsg = secret.createSecretMessage(versionNumber);
                byte[] valueToProtect = secretMsg.toByteArray();

                byte[] encryptedValueToProtect = dummyEncryptSecret(valueToProtect);

                DummyMerkledVssFactory merkledVss = new DummyMerkledVssFactory();
                // TODO: this is wrong. It seems that the valueToProtect has Secret. Secret has versionsMap. So
                //  for every version, we will end up sending all versions.
                List<byte[]> bytesForSharing = merkledVss.split(secret.getSecretId().getBytes(), versionNumber,
                        encryptedValueToProtect, numPairedHelpers, numPairedHelpers / 2);
                for (int i = 0; i < numPairedHelpers; i++) {
                    CommittedDeRecShare.DeRecShare derecShare =
                            new CommittedDeRecShare.DeRecShare(bytesForSharing.get(i),
                            new byte[]{1,2,3,4}, new byte[]{5,6,7,8}, secret.getSecretId(),
                                    versionNumber, "version's description");
                    // TODO: Calculate merkle root and paths for these DeRecShares
                    CommittedDeRecShare committedDeRecShare = new CommittedDeRecShare(derecShare,
                        new byte[] {4,3,2,1}, new ArrayList<>());
                    ShareImpl share = new ShareImpl(this.secret.getSecretId(), versionNumber, myStatus,
                            committedDeRecShare.createCommittedDeRecShareMessage().toByteArray());
//                    try {
//                        CommittedDeRecShare cds =
//                                new CommittedDeRecShare(Storeshare.CommittedDeRecShare.parseFrom(share.getCommittedDeRecShareBytes()));
//                        System.out.println("Committed DeRecShare (sending) is: " + cds.toString());
//                    } catch (InvalidProtocolBufferException ex) {
//                        System.out.println("Exception in trying to parse the constructed share as a committed derec " +
//                                "share");
//                        ex.printStackTrace();
//                    }
                    sharesMap.put(pairedHelpers.get(i), share);
                    if (!unsuccessfulVerificationRequests.containsKey(pairedHelpers.get(i))) {
                        unsuccessfulVerificationRequests.put(pairedHelpers.get(i), 0);
                    }

                }
            }
            System.out.println("Created shares. Sharesmap size: " + sharesMap.size());
        } catch (Exception ex) {
            System.out.println("Exception in createShares");
            ex.printStackTrace();
        }
    }

    void sendSharesToPairedHelpers() {
        System.out.println("in sendSharesToPairedHelpers - isPRotected=" + isProtected());
        if (sharesMap.isEmpty()) {
            createShares();
        } else {
            System.out.println("Sharesmap is not empty - not creating");
        }
        for ( HashMap.Entry<DeRecHelperStatus, ShareImpl>entry : sharesMap.entrySet()) {
            ShareImpl share = entry.getValue();
            if (!share.isConfirmed()) {
                System.out.println("************************************************ ************ *Sending share to " + entry.getKey().getId().getName());

                StoreShareMessages.sendStoreShareRequestMessage(
                        LibState.getInstance().getMeSharer().getMyLibId().getMyId(),
                        entry.getKey().getId(),
                        secret.getSecretId(),
                        LibState.getInstance().getMeSharer().getMyLibId().getPublicEncryptionKeyId(),
                        share);
            } else {
                System.out.println("ShareImpl is already confirmed");
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

            // Every time we send a verification request, increment the unsuccessful verification count by 1.
            unsuccessfulVerificationRequests.put(entry.getKey(),
                    unsuccessfulVerificationRequests.get(entry.getKey()) + 1);
            logger.info("Incremented unsuccessfulVerificationRequests by 1 for " + entry.getKey());


            if (unsuccessfulVerificationRequests.get(entry.getKey()) > LibState.getInstance().thresholdToMarkHelperFailed) {
                // If the number of unanswered/failed verification requests is greater than
                // thresholdToMarkHelperFailed, set the helper status to FAILED, and recalculate shares.
                if (entry.getKey().getStatus() == DeRecPairingStatus.PairingStatus.REFUSED) {
                    ((HelperStatusImpl) entry.getKey()).setStatus(DeRecPairingStatus.PairingStatus.FAILED);
                    secret.helperStatusChanged();
                }
                 createShares();
                System.out.println("HELPER FAILED VERIFICATION");
            } else if (unsuccessfulVerificationRequests.get(entry.getKey()) > LibState.getInstance().thresholdToMarkHelperRefused) {
                // If the number of unanswered/failed verification requests is greater than thresholdToMarkHelperRefused, set that helper's pairing
                // status to REFUSED. We hope that the helper can come back.
                if (entry.getKey().getStatus() == DeRecPairingStatus.PairingStatus.PAIRED) {
                    ((HelperStatusImpl) entry.getKey()).setStatus(DeRecPairingStatus.PairingStatus.REFUSED);
                }
                // createShares(); we don't recreate shares here
                System.out.println("HELPER REFUSED VERIFICATION");
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
                    System.out.println("Could not find helper status for sender: " + helperId.getName());
                    return false;
                }

                DeRecHelperStatus helperStatus = helperStatusOptional.get();

//                if (helperStatus == null) {
//                    System.out.println("Could not find helper status for sender: " + helperId.getName());
//                    return;
//                } else {
                    ShareImpl share = getShare(helperStatus);
                    if (share == null) {
                        // The share can be null if we had previously sent a verification request to a helper
                        // that we later removed or declared inactive before they could respond.
                        return false;
                    }
                    byte [] expectedHash = calculateVerificationHash(share.getCommittedDeRecShareBytes(), messageNonce);
                    System.out.println("Expected hash: V(" + versionNumber + ") " + Base64.getEncoder().encodeToString(expectedHash));
                    System.out.println("Received hash: V(" + messageVersionNumber + ") " + Base64.getEncoder().encodeToString(messageHash));
                    if (Arrays.equals(expectedHash, messageHash)) {
                        // Re-verify that this share is still confirmed
                        updateConfirmationShareStorage(helperStatus, true);
                        System.out.println("hashes matched");
                        unsuccessfulVerificationRequests.put(helperStatus, 0);
                        if (helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.REFUSED) {
                            ((HelperStatusImpl) helperStatus).setStatus(DeRecPairingStatus.PairingStatus.PAIRED);
//                            createShares();
                        }
                        ((HelperStatusImpl) helperStatus).setLastVerificationTime(Instant.now());
                        return true;
                    } else {
                        updateConfirmationShareStorage(helperStatus, false);
                        System.out.println("hashes not matched");
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
