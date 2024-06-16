package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;


import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
//import org.derecalliance.derec.lib.LibIdentity;
//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Version;
//import org.derecalliance.derec.lib.utils.UuidUtils;
import org.derecalliance.derec.protobuf.Storeshare;

import static org.derecalliance.derec.lib.impl.utils.MiscUtils.*;
import static org.derecalliance.derec.lib.impl.utils.MiscUtils.writeToByteArrayOutputStream;

//import static org.derecalliance.derec.lib.utils.MiscUtils.*;


public class SecretImpl implements DeRecSecret {

        DeRecSecret.Id id;
        String description;
        ArrayList<HelperStatusImpl> helperStatuses;

        boolean isRecovering;
        TreeMap<Integer, VersionImpl> versionsMap;  // Semantically, this is the keepList from the sharer's side

        private static DeRecSecret.Id generateId(String description) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-384");
                byte[] hash = digest.digest(description.getBytes());
                byte[] last16Bytes = new byte[16];
                System.arraycopy(hash, hash.length - 16, last16Bytes, 0, 16);
                DeRecSecret.Id id = new DeRecSecret.Id(last16Bytes);
                return id;
            } catch (Exception ex) {
                System.out.println("Exception in generateId");
                ex.printStackTrace();
                throw new RuntimeException("Could not generateId");
            }
        }

        public SecretImpl(String description, byte[] bytesToProtect,
                      List<DeRecIdentity> helperIds, boolean recovery) {
            this(generateId(description), description, bytesToProtect, helperIds, recovery);
        }

        public SecretImpl(Id secretId, String description, byte[] bytesToProtect,
                      List<DeRecIdentity> helperIds, boolean recovery) {
            try {
                this.id = secretId;
                this.description = description;

                helperStatuses = new ArrayList<>();
                if (helperIds.size() > 0) {
//            addHelpers(helperIds);
                    addHelpersAsync(helperIds);
                }
                versionsMap = new TreeMap<>();
//            if (bytesToProtect != null) {
//                // Create a version implicitly
//                //        VersionImpl v = new VersionImpl(this, bytesToProtect);
//                //        versionsMap.put(v.getVersionNumber(), v);
//            }
                // Create a version implicitly if there is data in bytesToProtect
                if (bytesToProtect != null && recovery == false) {
                    updateAsync(bytesToProtect);
                }
                isRecovering = recovery;
            } catch (Exception ex) {
                System.out.println("Exception in secret constructor");
                ex.printStackTrace();
            }
        }
        public SecretImpl(String description, byte[] bytesToProtect, boolean recovery) {
            this(description, bytesToProtect, new ArrayList<>(), recovery);
        }

        @Override
        public void addHelpers(List<? extends DeRecIdentity> helperIds) {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
        }

        @Override
        public List<CompletableFuture<? extends DeRecHelperStatus>> addHelpersAsync(List<? extends DeRecIdentity> helperIds) {
            return processAddHelpersAsync(helperIds, true);
        }
        public List<CompletableFuture<? extends DeRecHelperStatus>> processAddHelpersAsync(List<? extends DeRecIdentity> helperIds, boolean shouldStartPairing) {
            helperIds.forEach(helperId -> {
                long fakeNonce = 1111L; // This API should include nonce per
                LibState.getInstance().messageHashToIdentityMap.put(ByteString.copyFrom(helperId.getPublicEncryptionKeyDigest()),
                        helperId);
                // helper id that is scanned from the QR code
                var helperStatus = new HelperStatusImpl(this, helperId, fakeNonce);
                if (shouldStartPairing == true) {
                    helperStatus.startPairing(this.id, helperStatus.getId(), fakeNonce);
                }
                if (shouldStartPairing == false) {
                    System.out.println("Helper status found: " + helperStatus.toString());
                }
                this.helperStatuses.add(helperStatus);
            });
            return null;
        }

    public void addRecoveredHelper(HelperStatusImpl helperStatus) {
        System.out.println("########## INSTALLING FREE HELPER: " + helperStatus.getId().getName() + " - " + helperStatus.toString());
        helperStatus.setSecret(this);
        this.helperStatuses.add(helperStatus);
    }


        @Override
        public List<? extends DeRecHelperStatus> getHelperStatuses() {
            return  helperStatuses;
        }

        @Override
        public void removeHelpers(List<? extends DeRecIdentity> helperIds) {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
        }

        @Override
        public List<CompletableFuture<? extends DeRecHelperStatus>> removeHelpersAsync(List<? extends DeRecIdentity> helperIds) {
            System.out.println("In removeHelpersAsync");
            for (DeRecIdentity helperId: helperIds) {
                System.out.println("Removing helper: " + helperId.getName());
                var toBeRemoved =
                        helperStatuses.stream().filter(hs -> hs.getId().getPublicEncryptionKey().equals(helperId.getPublicEncryptionKey())).findFirst();
                if (toBeRemoved.isPresent()) {
                    System.out.println("Found helper to remove: " + toBeRemoved.get().getId().getName());
                    Timer timer = new Timer();
                    TimerTask task = new TimerTask() {
                        @Override
                        public void run() {
                            System.out.println("Timer expired in Secret");
                            helperStatuses.remove(toBeRemoved.get());
                        }
                    };
                    timer.schedule(task, 20000);

                    UnpairMessages.sendUnpairRequestMessage(LibState.getInstance().getMeSharer().getMyLibId().getMyId(),
                            toBeRemoved.get().getId(), id,
                            LibState.getInstance().getMeSharer().getMyLibId().getPublicEncryptionKeyId(),
                            "Please unpair with me");
                    System.out.println("Changing the pairing status from: " + toBeRemoved.get().getStatus());
                    toBeRemoved.get().setStatus(DeRecPairingStatus.PairingStatus.PENDING_REMOVAL);
                    LibState.getInstance().getMeSharer().deliverNotification(DeRecStatusNotification.StandardNotificationType.HELPER_UNPAIRED,
                            DeRecStatusNotification.NotificationSeverity.NORMAL,
                            "Helper unpaired - " + toBeRemoved.get().getId().getName(),
                            this, null, toBeRemoved.get());
                    System.out.println("to: " + toBeRemoved.get().getStatus());
                    for (VersionImpl version : versionsMap.values()) {
                        version.createShares();
                    }
                } else {
                    System.out.println("******* Could not find the helper to remove");
                }
            }
            return null;
        }

        @Override
        public DeRecVersion update() {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public DeRecVersion update(byte[] bytesToProtect) {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public DeRecVersion update(byte[] bytesToProtect, String description) {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public Future<? extends DeRecVersion> updateAsync() {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public Future<? extends DeRecVersion> updateAsync(byte[] bytesToProtect) {
//        Integer newVersionNumber = getMaxVersionNumber() + 1;
//        VersionImpl v = new VersionImpl(this, bytesToProtect, newVersionNumber);
//        versionsMap.put(newVersionNumber, v);
//        return null;

            int newVersionNumber = getMaxVersionNumber() + 1;

            LibState.getInstance().getMeSharer().deliverNotification(
                    DeRecStatusNotification.StandardNotificationType.UPDATE_PROGRESS,
                    DeRecStatusNotification.NotificationSeverity.NORMAL,
                    "Creating version # " + newVersionNumber,
                    this, null, null);

            return updateAsync(newVersionNumber, bytesToProtect);
        }

        @Override
        public Future<? extends DeRecVersion> updateAsync(byte[] bytesToProtect, String description) {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public Id getSecretId() {
            return id;
        }

        @Override
        public NavigableMap<Integer, ? extends DeRecVersion> getVersions() {
            return versionsMap;
        }


        public Future<? extends DeRecVersion> updateAsync(int versionNumber, byte[] bytesToProtect) {
            VersionImpl v = new VersionImpl(this, bytesToProtect, versionNumber);
            versionsMap.put(versionNumber, v);

            updateKeepListIfNeeded();
            return null;
        }

        public void addVersion(int versionNumber, VersionImpl version) {
            versionsMap.put(versionNumber, version);
        }

        public VersionImpl getVersionByNumber(int versionNumber) {
            return versionsMap.get(versionNumber);
        }

        public void deleteVersion(int versionNumber) {
            versionsMap.remove(versionNumber);
        }

        public int getMaxVersionNumber() {
            return versionsMap.isEmpty() ? 0 : Collections.max(versionsMap.keySet());
        }

        @Override
        public boolean isAvailable() {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return false;
        }

        @Override
        public boolean isClosed() {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return false;
        }

        @Override
        public CompletableFuture<? extends DeRecSecret> closeAsync() {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public String getDescription() {
            return description;
        }
        @Override
        public boolean isRecovering() {
            return isRecovering;
        }
        @Override
        public void setRecovering(boolean recovering) {
            isRecovering = recovering;
        }

        @Override
        public void close() {
            System.out.println("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
            Thread.currentThread().getStackTrace();
        }
        public String debugStr() {
            String str = "";
            for (Map.Entry<Integer, VersionImpl> entry : versionsMap.entrySet()) {
                str += "VersionImpl number: " + entry.getKey() + ", Value: " + entry.getValue().debugStr() + "\n";
            }
            return str;
        }

        void updateKeepListIfNeeded() {
            // Find the latest protected VersionImpl object
            Optional<Map.Entry<Integer, VersionImpl>> highestProtectedVersionImpl = versionsMap.entrySet().stream()
                    .filter(entry -> entry.getValue().isProtected())
                    .max(Map.Entry.comparingByKey());

            System.out.println("Evaluating if versions can be deleted");
            if (highestProtectedVersionImpl.isPresent()) {
                System.out.println("highest protected version number is " + highestProtectedVersionImpl.get().getValue().getVersionNumber());
            }
            ArrayList<Integer> versionsToDelete = new ArrayList<>();
            versionsMap.forEach((versionNumber, versionImpl) -> {
                System.out.println("Seeing if we can delete version " + versionNumber);
                if (highestProtectedVersionImpl.isPresent() && versionNumber < highestProtectedVersionImpl.get().getValue().getVersionNumber()) {
                    System.out.printf("Deleting version %d because %d is the highest protected version\n",
                            versionNumber, highestProtectedVersionImpl.get().getKey());
                    versionsToDelete.add(versionNumber);
                }
            });
            System.out.println("Versions to be deleted: " + versionsToDelete);
            versionsToDelete.forEach(this::deleteVersion);
        }

        void helperStatusChanged() {
            if (!isRecovering) {
                updateKeepListIfNeeded();
                createNewVersionForHelperStatusChanged();
            }
        }

    void createNewVersionForHelperStatusChanged() {
        int mostRecentVersionNumber = getMaxVersionNumber();
        VersionImpl mostRecentVersion = versionsMap.get(mostRecentVersionNumber);
        updateAsync(mostRecentVersion.protectedValue);
    }

    DeRecHelperStatus getHelperStatusById(DeRecIdentity helperId) {
        var helperStatus = helperStatuses.stream()
                .filter(hs -> hs.getId().getPublicEncryptionKey().equals(helperId.getPublicEncryptionKey()))
                .findFirst();
        return helperStatus.orElse(null);
    }

    public void removeVersionFromKeepList(Integer versionNumber) {
            deleteVersion(versionNumber);
    }


/*
    public byte[] serialize() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            // Serialize secret id
            byte[] idBytes = id.getBytes();
            baos.write(intToByteArray(idBytes.length));
            baos.write(idBytes);

            // Serialize description
            byte[] descriptionBytes = description.getBytes();
            baos.write(intToByteArray(descriptionBytes.length));
            baos.write(descriptionBytes);

            // Serialize isRecovering
            baos.write(isRecovering ? 1 : 0);

            // Serialize versionsMap
            baos.write(intToByteArray(versionsMap.size())); // Prepend map size
            for (Map.Entry<Integer, VersionImpl> entry : versionsMap.entrySet()) {
                baos.write(intToByteArray(entry.getKey())); // Write version number
                byte[] protectedValue = entry.getValue().getProtectedValue();
                baos.write(intToByteArray(protectedValue.length)); // Prepend length of protectedValue
                baos.write(protectedValue);
            }

            return baos.toByteArray();
        }
    }

    public Secret deserialize(byte[] data) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
//            MyClass myClass = new MyClass();

            // Deserialize id
            byte[] idBytes = readByteArray(bais);
            DeRecSecret.Id secretId = new DeRecSecret.Id(idBytes);

            // Deserialize description
            byte[] descriptionBytes = readByteArray(bais);
            String description = new String(descriptionBytes);

            // Deserialize isRecovering
            boolean isRecovering = bais.read() != 0;

            Secret secret = new Secret(secretId, description, null,
            new ArrayList<DeRecIdentity>(), isRecovering);

            // Deserialize versionsMap, create VersionImpl objects and add to the secretMap
            TreeMap<Integer, VersionImpl> versionsMap = new TreeMap<>();
            int versionsMapSize = readInt(bais);
            for (int i = 0; i < versionsMapSize; i++) {
                int readVersionNumber = readInt(bais);
                byte[] readProtectedValue = readByteArray(bais);
                VersionImpl version = new VersionImpl(secret, readProtectedValue,  readVersionNumber);
                secret.addVersion(readVersionNumber, version);
            }

            return secret;
        }
    }
 */


//    private String readStringFromByteArrayInputStream(ByteArrayInputStream bais) throws IOException {
//        byte[] stringBytes = readByteArrayFromByteArrayInputStream(bais);
//        return new String(stringBytes);
//    }


        public Storeshare.Secret createSecretMessage(int versionNumber) {
            try {
                Instant now = Instant.now();
                Timestamp timestamp = Timestamp.newBuilder().setSeconds(now.getEpochSecond()).setNanos(now.getNano()).build();

                // Write fields from the Secret object
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                writeToByteArrayOutputStream(baos, id.getBytes()); // secret id
                writeToByteArrayOutputStream(baos, description.getBytes());
                baos.write(isRecovering ? 1 : 0);
                baos.write(intToByteArray(versionNumber)); // versionNumber
                writeToByteArrayOutputStream(baos, versionsMap.get(versionNumber).getProtectedValue());
                // TODO: These keys should be defined in the Secret protobuf in StoreShare.proto
                writeToByteArrayOutputStream(baos,
                        LibState.getInstance().getMeSharer().getMyLibId().getEncryptionPrivateKey().getBytes());
                writeToByteArrayOutputStream(baos,
                        LibState.getInstance().getMeSharer().getMyLibId().getEncryptionPublicKey().getBytes());
                baos.write(intToByteArray(LibState.getInstance().getMeSharer().getMyLibId().getPublicEncryptionKeyId()));
                writeToByteArrayOutputStream(baos,
                        LibState.getInstance().getMeSharer().getMyLibId().getSignaturePrivateKey().getBytes());
                writeToByteArrayOutputStream(baos,
                        LibState.getInstance().getMeSharer().getMyLibId().getSignaturePublicKey().getBytes());
                baos.write(intToByteArray(LibState.getInstance().getMeSharer().getMyLibId().getPublicSignatureKeyId()));

                baos.write(intToByteArray(helperStatuses.size())); // map size
                for (var helperStatus : helperStatuses) {
                    byte[] serializedHelperId = IdentityImpl.serializeDeRecIdentity(helperStatus.getId());
                    writeToByteArrayOutputStream(baos, serializedHelperId);
                    baos.write(intToByteArray(helperStatus.pairingStatus.ordinal()));
                }
                Storeshare.Secret secretMessage = Storeshare.Secret.newBuilder()
                        .setSecretData(ByteString.copyFrom(baos.toByteArray()))
                        .setPrivateEncryptionKey(LibState.getInstance().getMeSharer().getMyLibId().getEncryptionPrivateKey())
                        .setPrivateSignatureKey(LibState.getInstance().getMeSharer().getMyLibId().getSignaturePrivateKey())
                        .setCreationTime(timestamp)
                        .setHelperThresholdForRecovery(LibState.getInstance().getMinNumberOfHelpersForRecovery())
                        .setHelperThresholdForConfirmingShareReceipt(LibState.getInstance().getMinNumberOfHelpersForConfirmingShareReceipt())
                        .build();
                return secretMessage;
            } catch (Exception ex) {
                System.out.printf("Exception in createSecretMessage");
                ex.printStackTrace();
                return null;
            }
        }

        // Has a side effect that it updates the public/private encryption/signature keys in the LibState from the
        // recovered secret.
        public static SecretImpl parseSecretMessage(DeRecSecret.Id secretId, byte[] serializedSecretMessage) {
            try {
                System.out.println("In parseSec message size: " + serializedSecretMessage.length);
                Storeshare.Secret secretMessage = Storeshare.Secret.parseFrom(serializedSecretMessage);
                System.out.println("parsed secretmessage");
                System.out.println("secret data size: " + secretMessage.getSecretData().size());

                ByteArrayInputStream bais = new ByteArrayInputStream(secretMessage.getSecretData().toByteArray());

                byte[] idBytes = readByteArrayFromByteArrayInputStream(bais);
                String description = new String(readByteArrayFromByteArrayInputStream(bais));
                boolean isRecovering = bais.read() == 1 ? true : false;
                int versionNumber = readIntFromByteArrayInputStream(bais);
                byte[] protectedValue = readByteArrayFromByteArrayInputStream(bais);

                System.out.println("Read protected value of size: " + protectedValue.length);

                String encryptionPrivateKey = new String(readByteArrayFromByteArrayInputStream(bais));
                String encryptionPublicKey = new String(readByteArrayFromByteArrayInputStream(bais));
                int publicEncryptionKeyId = readIntFromByteArrayInputStream(bais);
                String signaturePrivateKey = new String(readByteArrayFromByteArrayInputStream(bais));
                String signaturePublicKey = new String(readByteArrayFromByteArrayInputStream(bais));
                int publicSignatureKeyId = readIntFromByteArrayInputStream(bais);

                System.out.println("Read keys");
                // Read helperStatuses
                int mapSize = readIntFromByteArrayInputStream(bais);
                ArrayList<DeRecIdentity> helperIds = new ArrayList<DeRecIdentity>();
                HashMap<DeRecIdentity, DeRecPairingStatus.PairingStatus> recoveredPairingStatuses = new HashMap<>();
                for (int i = 0; i < mapSize; i++) {
                    byte[] serializedHelperId = readByteArrayFromByteArrayInputStream(bais);
                    DeRecIdentity recoveredHelperId = IdentityImpl.deserializeDeRecIdentity(serializedHelperId);
                    helperIds.add(recoveredHelperId);
                    DeRecPairingStatus.PairingStatus recoveredPairingStatus =
                            DeRecPairingStatus.PairingStatus.values()[readIntFromByteArrayInputStream(bais)];
                    recoveredPairingStatuses.put(recoveredHelperId, recoveredPairingStatus);
                }

                System.out.println("Read helper statuses: count: " + helperIds.size());
                for (DeRecIdentity helperId : helperIds) {
                    System.out.print("Helper Id: " + helperId.getName() + ", contact: " + helperId.getContact() + ", " +
                            "address: " + helperId.getAddress());
                    System.out.println(" - with pairing status: " + recoveredPairingStatuses.get(helperId));
                }

                System.out.println("Calling newSecret with idBytes " + idBytes );
                System.out.println("desc: " + description);

                SecretImpl secret = new SecretImpl(new DeRecSecret.Id(idBytes), description, null,
                        new ArrayList<>(), false);
                System.out.println("Created new secret");

                secret.processAddHelpersAsync(helperIds, false);
                System.out.println("Added helper ids without pairing to the secret");

                for (DeRecIdentity helperId : helperIds) {
                    HelperStatusImpl helperStatus = (HelperStatusImpl) secret.getHelperStatusById(helperId);
                    if (helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.NONE) {
                        System.out.println("Setting helper status of " + helperStatus.getId().getName() + " to " + recoveredPairingStatuses.get(helperId));
                        helperStatus.setStatus(recoveredPairingStatuses.get(helperId));
                    }
                }

                VersionImpl version = new VersionImpl(secret, protectedValue, versionNumber);
                System.out.println("Created new version");
                byte[] v1pv = version.getProtectedValue();
                System.out.println("v1pv: size " + v1pv.length);
                System.out.println("v1pv: str " + new String(v1pv));

                secret.addVersion(versionNumber, version);
                System.out.println("Added version as version-" + versionNumber);

//            LibState.getInstance().getMeSharer().getMyLibId().setKeys(encryptionPrivateKey, encryptionPublicKey, signaturePrivateKey,
//                    signaturePublicKey, publicEncryptionKeyId, publicSignatureKeyId);
                LibState.getInstance().getMeSharer().getMyLibId().setVariables(
                        LibState.getInstance().getMeSharer().getMyLibId().getMyId().getName(),
                        LibState.getInstance().getMeSharer().getMyLibId().getMyId().getContact(),
                        LibState.getInstance().getMeSharer().getMyLibId().getMyId().getAddress(),
                        encryptionPrivateKey, encryptionPublicKey, signaturePrivateKey,
                        signaturePublicKey, publicEncryptionKeyId, publicSignatureKeyId);

                System.out.println("Updated keys in Libstate");
                return secret;
            } catch (Exception ex) {
                System.out.printf("Exception in parseSecretMessage");
                ex.printStackTrace();
                return null;
            }
        }

    public void periodicWorkForSecret() {
        System.out.println("Processing secret: " + getSecretId());
        NavigableMap<Integer, VersionImpl> versions = (NavigableMap<Integer, VersionImpl>) getVersions();
        if (isRecovering()) {
            LibState.getInstance().getMeSharer().getRecoveryContext().evaluateAndSendGetShareRequests(getSecretId());
        } else {
            for (VersionImpl version : versions.values()) {
                version.sendSharesToPairedHelpers();
                version.sendVerificationRequestsToPairedHelpers();
            }
        }
    }
}
