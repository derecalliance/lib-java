package org.derecalliance.derec.lib.impl;

import static org.derecalliance.derec.lib.impl.MessageFactory.*;
import static org.derecalliance.derec.lib.impl.ProtobufHttpClient.sendHttpRequest;
import static org.derecalliance.derec.lib.impl.utils.MiscUtils.*;
import static org.derecalliance.derec.lib.impl.utils.MiscUtils.writeToByteArrayOutputStream;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.lib.impl.commands.AddHelpersCommand;
import org.derecalliance.derec.lib.impl.commands.RemoveHelpersCommand;
import org.derecalliance.derec.lib.impl.commands.UpdateCommand;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.Storeshare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecretImpl implements DeRecSecret {
    LibIdentity libId;
    DeRecSecret.Id id;
    String description;
    ArrayList<HelperStatusImpl> helperStatuses;
    boolean isRecovering;
    boolean isClosed; // is this secret shut down/closed?
    TreeMap<Integer, VersionImpl> versionsMap; // Semantically, this is the keepList from the sharer's side

    // When a new version (n) is created, it gets confirmed after the helpers receive the shares.
    // When the version n is confirmed, we need to send a StoreShareRequestMessage just with the
    // keepList (but no share) so that the helpers can delete version (n-1). This map is used to record
    // the updated KeepList to send to individual helpers.
    HashMap<HelperStatusImpl, List<Integer>> versionsToCleanupFromHelpers = new HashMap();
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private static DeRecSecret.Id generateId(String description) {
        Logger staticLogger = LoggerFactory.getLogger(SecretImpl.class.getName());
        try {
            // TODO: this should generate a random secret id, not take the last 16 bytes of the hash of the secret name
            MessageDigest digest = MessageDigest.getInstance("SHA-384");
            byte[] hash = digest.digest(description.getBytes());
            byte[] last16Bytes = new byte[16];
            System.arraycopy(hash, hash.length - 16, last16Bytes, 0, 16);
            DeRecSecret.Id id = new DeRecSecret.Id(last16Bytes);
            return id;
        } catch (Exception ex) {
            staticLogger.error("Exception in generateId", ex);
            throw new RuntimeException("Could not generateId");
        }
    }

    public SecretImpl(String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
        this(generateId(description), description, bytesToProtect, helperIds, recovery);
    }

    public SecretImpl(
            Id secretId, String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
        try {
            this.id = secretId;
            this.description = description;

            libId = new LibIdentity(
                    LibState.getInstance().getMeSharer().getName(),
                    LibState.getInstance().getMeSharer().getContact(),
                    LibState.getInstance().getMeSharer().getAddress());
            logger.debug(
                    "Adding myself (Sharer) " + libId.getMyId().getName() + " to messageHashAndSecretIdToIdentityMap");
            LibState.getInstance()
                    .registerMessageHashAndSecretIdToIdentity(
                            ByteString.copyFrom(libId.getMyId().getPublicEncryptionKeyDigest()),
                            secretId,
                            libId.getMyId());

            logger.debug("Adding myself (Sharer) " + libId.getMyId().getName() + " to publicKeyToIdentityMap");
            LibState.getInstance().registerPublicKeyId(libId.getPublicEncryptionKeyId(), libId);

            // if there are helpers present in the list, pair with them for this secret
            helperStatuses = new ArrayList<>();
            if (helperIds.size() > 0) {
                addHelpersAsync(helperIds);
            }
            versionsMap = new TreeMap<>();
            // Create a version implicitly if there is data in bytesToProtect
            if (bytesToProtect != null && recovery == false) {
                updateAsync(bytesToProtect);
            }
            isRecovering = recovery;
            isClosed = false;
        } catch (Exception ex) {
            logger.error("Exception in secret constructor", ex);
        }
    }

    public SecretImpl(String description, byte[] bytesToProtect, boolean recovery) {
        this(description, bytesToProtect, new ArrayList<>(), recovery);
    }

    @Override
    public void addHelpers(List<? extends DeRecIdentity> helperIds) {
        //            logger.debug("Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() +
        // "\n");
        //            Thread.currentThread().getStackTrace();
        AddHelpersCommand command = new AddHelpersCommand(this, helperIds, true);
        LibState.getInstance().getCommandQueue().add(command);
        // Wait until all futures are complete
        List<CompletableFuture<? extends DeRecHelperStatus>> futures = command.getFutures();
        CompletableFuture<Void> allOf = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
        logger.debug("addHelpers - sync call blocking for allOf.join");
        allOf.join();
        logger.debug("addHelpers - sync call got unblocked from allOf.join");
    }

    @Override
    public List<CompletableFuture<? extends DeRecHelperStatus>> addHelpersAsync(
            List<? extends DeRecIdentity> helperIds) {
        AddHelpersCommand command = new AddHelpersCommand(this, helperIds, false);
        LibState.getInstance().getCommandQueue().add(command);
        return command.getFutures();
    }

    /**
     * Processes adding Helpers to this secret. Adds Helpers to data structures and initiates pairing.
     *
     * @param helperIds          List of DeRecIdentities of the Helpers to be added to the secret.
     * @param shouldStartPairing Whether a PairRequestMessage should be sent
     * @return List of DeRecHelperStatus objects
     */
    public List<DeRecHelperStatus> processAddHelpersAsync(
            List<? extends DeRecIdentity> helperIds, boolean shouldStartPairing) {
        ArrayList<DeRecHelperStatus> ret = new ArrayList<>();
        helperIds.forEach(helperId -> {
            long fakeNonce = 1111L; // This API should include nonce per pairing
            LibState.getInstance()
                    .registerMessageHashAndSecretIdToIdentity(
                            ByteString.copyFrom(helperId.getPublicEncryptionKeyDigest()), id, helperId);
            logger.debug("Added my helper " + helperId.getName() + " to messageHashToIdentityMap");
            LibState.getInstance().printMessageHashToIdentityMap();

            // helper id that is scanned from the QR code
            var helperStatus = new HelperStatusImpl(this, helperId, fakeNonce);
            this.helperStatuses.add(helperStatus);
            ret.add(helperStatus);
            if (shouldStartPairing == true) {
                helperStatus.startPairing(this.id, helperStatus.getId(), fakeNonce);
            }
            if (shouldStartPairing == false) {
                logger.debug("Helper status found: " + helperStatus.toString());
            }
        });
        return ret;
    }

    @Override
    public List<? extends DeRecHelperStatus> getHelperStatuses() {
        return helperStatuses;
    }

    @Override
    public void removeHelpers(List<? extends DeRecIdentity> helperIds) {
        LibState.getInstance().getCommandQueue().add(new RemoveHelpersCommand(this, helperIds));
    }

    @Override
    public List<CompletableFuture<? extends DeRecHelperStatus>> removeHelpersAsync(
            List<? extends DeRecIdentity> helperIds) {
        RemoveHelpersCommand command = new RemoveHelpersCommand(this, helperIds);
        LibState.getInstance().getCommandQueue().add(command);
        // Return futures or handle as needed
        // return List.of(command.getFuture());
        return (command.getFuture());
    }

    /**
     * Processes removing Helpers from this secret by unpairing with them.
     *
     * @param helperIds List of DeRecIdentities of the Helpers we want to remove from this secret.
     * @return List of HelperStatus objects of the Helpers removed
     */
    public List<HelperStatusImpl> processRemoveHelpersAsync(List<? extends DeRecIdentity> helperIds) {
        logger.debug("In processRemoveHelpersAsync");
        for (DeRecIdentity helperId : helperIds) {
            logger.debug("Removing helper: " + helperId.getName());
            // find the helper to remove
            var toBeRemoved = helperStatuses.stream()
                    .filter(hs -> hs.getId().getPublicEncryptionKey().equals(helperId.getPublicEncryptionKey()))
                    .findFirst();
            if (toBeRemoved.isPresent()) {
                logger.debug(
                        "Found helper to remove: " + toBeRemoved.get().getId().getName());
                Timer timer = new Timer();
                TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        logger.debug("Timer expired in Secret");
                        // remove the helper from the list of HelperStatus objects for this secret
                        helperStatuses.remove(toBeRemoved.get());
                    }
                };
                timer.schedule(task, 20000);

                UnpairMessages.sendUnpairRequestMessage(
                        libId.getMyId(),
                        toBeRemoved.get().getId(),
                        id,
                        libId.getPublicEncryptionKeyId(),
                        "Please unpair with me");
                logger.debug(
                        "Changing the pairing status from: " + toBeRemoved.get().getStatus());
                // update the pairing status of that helper to be removed
                toBeRemoved.get().setStatus(DeRecPairingStatus.PairingStatus.PENDING_REMOVAL);
                // notify the application
                LibState.getInstance()
                        .getMeSharer()
                        .deliverNotification(
                                DeRecStatusNotification.StandardNotificationType.HELPER_UNPAIRED,
                                DeRecStatusNotification.NotificationSeverity.NORMAL,
                                "Helper unpaired - " + toBeRemoved.get().getId().getName(),
                                this,
                                null,
                                toBeRemoved.get());
                logger.debug("to: " + toBeRemoved.get().getStatus());
                // since we removed a helper, we need to recalculate shares for this secret
                for (VersionImpl version : versionsMap.values()) {
                    version.createShares();
                }
            } else {
                logger.debug("******* Could not find the helper to remove");
            }
        }
        return null;
    }

    @Override
    public DeRecVersion update() {
        logger.debug(
                "Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
        logger.debug(
                Arrays.stream(Thread.currentThread().getStackTrace()).toList().toString());
        return null;
    }

    @Override
    public DeRecVersion update(byte[] bytesToProtect) {
        logger.debug(
                "Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
        logger.debug(
                Arrays.stream(Thread.currentThread().getStackTrace()).toList().toString());
        return null;
    }

    @Override
    public DeRecVersion update(byte[] bytesToProtect, String description) {
        logger.debug(
                "Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
        logger.debug(
                Arrays.stream(Thread.currentThread().getStackTrace()).toList().toString());
        return null;
    }

    @Override
    public Future<? extends DeRecVersion> updateAsync() {
        logger.debug(
                "Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
        logger.debug(
                Arrays.stream(Thread.currentThread().getStackTrace()).toList().toString());
        return null;
    }

    @Override
    public Future<? extends DeRecVersion> updateAsync(byte[] bytesToProtect) {

        UpdateCommand command = new UpdateCommand(this, bytesToProtect);
        LibState.getInstance().getCommandQueue().add(command);
        // Wait for completion or handle as needed
        return command.getFuture();
    }

    /**
     * Updates the secret asynchronously
     *
     * @param bytesToProtect Updated protected value of the secret
     * @return The up-to-date DeRecVersion of the secret
     */
    public DeRecVersion processUpdateAsync(byte[] bytesToProtect) {

        int newVersionNumber = getMaxVersionNumber() + 1;

        LibState.getInstance()
                .getMeSharer()
                .deliverNotification(
                        DeRecStatusNotification.StandardNotificationType.UPDATE_PROGRESS,
                        DeRecStatusNotification.NotificationSeverity.NORMAL,
                        "Creating version # " + newVersionNumber,
                        this,
                        null,
                        null);

        return processUpdateAsync(newVersionNumber, bytesToProtect);
    }

    @Override
    public Future<? extends DeRecVersion> updateAsync(byte[] bytesToProtect, String description) {
        logger.debug(
                "Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
        logger.debug(
                Arrays.stream(Thread.currentThread().getStackTrace()).toList().toString());
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
        UpdateCommand command = new UpdateCommand(this, bytesToProtect);
        LibState.getInstance().getCommandQueue().add(command);
        // Return future or handle as needed
        return command.getFuture();
    }

    /**
     * Updates the secret asynchronously, and updates the KeepList accordingly.
     *
     * @param versionNumber  Updated version number
     * @param bytesToProtect Updated protected value of the secret
     * @return The up-to-date DeRecVersion object
     */
    public DeRecVersion processUpdateAsync(int versionNumber, byte[] bytesToProtect) {
        VersionImpl v = new VersionImpl(this, bytesToProtect, versionNumber);
        versionsMap.put(versionNumber, v);

        updateKeepListIfNeeded();
        return null;
    }

    /**
     * Adds a version to the versionsMap
     *
     * @param versionNumber Version number to be added
     * @param version       Version object to be added
     */
    public void addVersion(int versionNumber, VersionImpl version) {
        versionsMap.put(versionNumber, version);
    }

    /**
     * Gets a version of the secret based on its version number
     *
     * @param versionNumber Version number
     * @return Version object
     */
    public VersionImpl getVersionByNumber(int versionNumber) {
        return versionsMap.get(versionNumber);
    }

    /**
     * Removes a version from VersionsMap
     *
     * @param versionNumber Version number
     */
    public void deleteVersion(int versionNumber) {
        versionsMap.remove(versionNumber);
    }

    /**
     * Gets the highest version number for this secret
     *
     * @return int highest version number
     */
    public int getMaxVersionNumber() {
        return versionsMap.isEmpty() ? 0 : Collections.max(versionsMap.keySet());
    }

    @Override
    public boolean isAvailable() {
        // The comment for this API says: the secret is in a state where updates can be safely made and if it
        // is not closed, then the secret is available.
        // In this implementation, if the secret is not closed, it's always available.
        return isClosed ? false : true;
    }

    @Override
    public boolean isClosed() {
        return isClosed;
    }

    @Override
    public CompletableFuture<? extends DeRecSecret> closeAsync() {
        logger.debug(
                "Not implemented: " + Thread.currentThread().getStackTrace()[2].getMethodName() + "\n");
        logger.debug(
                Arrays.stream(Thread.currentThread().getStackTrace()).toList().toString());
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

    public void setRecovering(boolean recovering) {
        isRecovering = recovering;
    }

    @Override
    public void close() {
        // TODO: unpair with helpers and gracefully close the secret
        LibState.getInstance().getMeSharer().removeSecret(this.getSecretId());
        isClosed = true;
    }

    public String debugStr() {
        String str = "";
        for (Map.Entry<Integer, VersionImpl> entry : versionsMap.entrySet()) {
            str += "VersionImpl number: " + entry.getKey() + ", Value: "
                    + entry.getValue().debugStr() + "\n";
        }
        return str;
    }

    /**
     * Updates the keepList based on which versions are protected.
     * Keeps the highest protected version number plus subsequent unprotected versions in the keepList
     */
    void updateKeepListIfNeeded() {
        // Find the latest protected VersionImpl object
        Optional<Map.Entry<Integer, VersionImpl>> highestProtectedVersionImpl = versionsMap.entrySet().stream()
                .filter(entry -> entry.getValue().isProtected())
                .max(Map.Entry.comparingByKey());

        logger.debug("Evaluating if versions can be deleted");
        if (highestProtectedVersionImpl.isPresent()) {
            logger.debug("highest protected version number is "
                    + highestProtectedVersionImpl.get().getValue().getVersionNumber());

            ArrayList<Integer> versionsToDelete = new ArrayList<>();
            versionsMap.forEach((versionNumber, versionImpl) -> {
                logger.debug("Seeing if we can delete version " + versionNumber);
                if (versionNumber < highestProtectedVersionImpl.get().getValue().getVersionNumber()) {
                    logger.debug("Deleting version " + versionNumber + " because "
                            + highestProtectedVersionImpl.get().getKey() + " is the highest protected version");
                    versionsToDelete.add(versionNumber);
                }
            });

            logger.debug("Versions to be deleted: " + versionsToDelete);
            versionsToDelete.forEach(this::deleteVersion);
            if (versionsToDelete.size() > 0) {
                logger.debug("I have versions to delete. I will send empty StoreShareRequestMessage");
                for (HelperStatusImpl helperStatus : helperStatuses) {
                    if (helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.PAIRED) {
                        versionsToCleanupFromHelpers.put(
                                helperStatus, versionsMap.keySet().stream().toList());
                    }
                }
                logger.debug("versionsToCleanupFromHelpers: ");
                for (HelperStatusImpl helperStatus : versionsToCleanupFromHelpers.keySet()) {
                    logger.debug("Helper: " + helperStatus.getId().getName() + ", KeepList: "
                            + versionsToCleanupFromHelpers.get(helperStatus));
                }
                logger.debug("-- end of versionsToCleanupFromHelpers");
            }
        }
    }

    /**
     * Updates keepList and version numbers based on adding/losing a helper
     */
    void helperStatusChanged() {
        if (!isRecovering) {
            updateKeepListIfNeeded();
            createNewVersionForHelperStatusChanged();
        }
    }

    /**
     * Creates a new version whenever a HelperStatus changes (i.e. pairing status changes for a HelperStatus)
     */
    void createNewVersionForHelperStatusChanged() {
        int mostRecentVersionNumber = getMaxVersionNumber();
        VersionImpl mostRecentVersion = versionsMap.get(mostRecentVersionNumber);
        updateAsync(mostRecentVersion.protectedValue);
    }

    /**
     * Gets the HelperStatus object by its DeRecIdentity
     *
     * @param helperId DeRecIdentity of the Helper
     * @return HelperStatus object
     */
    DeRecHelperStatus getHelperStatusById(DeRecIdentity helperId) {
        var helperStatus = helperStatuses.stream()
                .filter(hs -> hs.getId().getPublicEncryptionKey().equals(helperId.getPublicEncryptionKey()))
                .findFirst();
        return helperStatus.orElse(null);
    }

    /**
     * This is called when we finish recovering, so that we can clear the helper who helped us recover, and replace
     * them with their original self.
     */
    public void clearOneHelper(DeRecIdentity helperId) {
        helperStatuses.remove((HelperStatusImpl) getHelperStatusById(helperId));
    }

    public void removeVersionFromKeepList(Integer versionNumber) {
        deleteVersion(versionNumber);
    }

    /**
     * Serializes all information needed in a Secret. This information is put in the protobuf Secret message.
     * Enough information must be put in the serialized Secret, because this is what the Sharer gets back in recovery mode.
     *
     * @param versionNumber version number of the Version we want to protect
     * @return protobuf-serialized Secret message.
     */
    public Storeshare.Secret createSecretMessage(int versionNumber) {
        try {
            Instant now = Instant.now();
            Timestamp timestamp = Timestamp.newBuilder()
                    .setSeconds(now.getEpochSecond())
                    .setNanos(now.getNano())
                    .build();

            // Write fields from the Secret object
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writeToByteArrayOutputStream(baos, id.getBytes()); // secret id
            writeToByteArrayOutputStream(baos, description.getBytes());
            baos.write(isRecovering ? 1 : 0);
            baos.write(intToByteArray(versionNumber)); // versionNumber
            writeToByteArrayOutputStream(baos, versionsMap.get(versionNumber).getProtectedValue());
            // TODO: These keys should be defined in the Secret protobuf in StoreShare.proto
            writeToByteArrayOutputStream(baos, libId.getEncryptionPrivateKey().getBytes());
            writeToByteArrayOutputStream(baos, libId.getEncryptionPublicKey().getBytes());
            baos.write(intToByteArray(libId.getPublicEncryptionKeyId()));
            writeToByteArrayOutputStream(baos, libId.getSignaturePrivateKey().getBytes());
            writeToByteArrayOutputStream(baos, libId.getSignaturePublicKey().getBytes());
            baos.write(intToByteArray(libId.getPublicSignatureKeyId()));

            logger.debug("+++++++++++++ start");
            logger.debug("createSecretMessage encoded keys as follows");
            logger.debug("getEncryptionPrivateKey: " + libId.getEncryptionPrivateKey());
            logger.debug("getEncryptionPublicKey: " + libId.getEncryptionPublicKey());
            logger.debug("getPublicEncryptionKeyId(): " + libId.getPublicEncryptionKeyId());
            logger.debug("getSignaturePrivateKey(): " + libId.getSignaturePrivateKey());
            logger.debug("getSignaturePublicKey(): " + libId.getSignaturePublicKey());
            logger.debug("getPublicSignatureKeyId(): " + libId.getPublicSignatureKeyId());
            logger.debug("+++++++++++++ end");

            // publicKeyId -> helper's publicEncryptionKey mapping
            // Write the publicKeyIdToIdentityMap map so that when we recover, we can reinstantiate the
            // free-helpers that we didn't pair with during the recovery process
            // We just write the publicKeyId -> helper's publicKey. While restoring we create the map based on the
            // helpers's publicKey.
            baos.write(intToByteArray(helperStatuses.size())); // map size
            // write the HelperStatuses for this secret
            for (var helperStatus : helperStatuses) {
                byte[] serializedHelperId = IdentityImpl.serializeDeRecIdentity(helperStatus.getId());
                writeToByteArrayOutputStream(baos, serializedHelperId);
                baos.write(intToByteArray(helperStatus.pairingStatus.ordinal()));
            }
            Storeshare.Secret secretMessage = Storeshare.Secret.newBuilder()
                    .setSecretData(ByteString.copyFrom(baos.toByteArray()))
                    .setPrivateEncryptionKey(libId.getEncryptionPrivateKey())
                    .setPrivateSignatureKey(libId.getSignaturePrivateKey())
                    .setCreationTime(timestamp)
                    .setHelperThresholdForRecovery(LibState.getInstance().getMinNumberOfHelpersForRecovery())
                    .setHelperThresholdForConfirmingShareReceipt(
                            LibState.getInstance().getMinNumberOfHelpersForConfirmingShareReceipt())
                    .build();
            return secretMessage;
        } catch (Exception ex) {
            logger.error("Exception in createSecretMessage", ex);
            return null;
        }
    }

    /**
     * Deserializes the protobuf-serialized Secret message.
     *
     * @param sharer                  The sharer of this secret
     * @param recoveredState          RecoveredState object to be updated as the message is parsed
     * @param secretId                Secret Id
     * @param serializedSecretMessage The protobuf-serialized Secret message received
     */
    public static void parseSecretMessage(
            SharerImpl sharer, RecoveredState recoveredState, DeRecSecret.Id secretId, byte[] serializedSecretMessage) {
        Logger staticLogger = LoggerFactory.getLogger(SecretImpl.class.getName());

        try {
            staticLogger.debug("In parseSec message size: " + serializedSecretMessage.length);
            Storeshare.Secret secretMessage = Storeshare.Secret.parseFrom(serializedSecretMessage);
            staticLogger.debug("parsed secretmessage");
            staticLogger.debug(
                    "secret data size: " + secretMessage.getSecretData().size());

            ByteArrayInputStream bais =
                    new ByteArrayInputStream(secretMessage.getSecretData().toByteArray());

            // Read details of the secret (id, description, version number, etc.)
            byte[] idBytes = readByteArrayFromByteArrayInputStream(bais);
            String description = new String(readByteArrayFromByteArrayInputStream(bais));
            boolean isRecovering = bais.read() == 1 ? true : false;
            int versionNumber = readIntFromByteArrayInputStream(bais);
            byte[] protectedValue = readByteArrayFromByteArrayInputStream(bais);

            staticLogger.debug("Read protected value of size: " + protectedValue.length);

            // Read sharer's original keys (when they were in normal mode)
            String encryptionPrivateKey = new String(readByteArrayFromByteArrayInputStream(bais));
            String encryptionPublicKey = new String(readByteArrayFromByteArrayInputStream(bais));
            int publicEncryptionKeyId = readIntFromByteArrayInputStream(bais);
            String signaturePrivateKey = new String(readByteArrayFromByteArrayInputStream(bais));
            String signaturePublicKey = new String(readByteArrayFromByteArrayInputStream(bais));
            int publicSignatureKeyId = readIntFromByteArrayInputStream(bais);

            staticLogger.debug("+++++++++++++ start");
            staticLogger.debug("parseSecretMessage decoded keys as follows");
            staticLogger.debug("getEncryptionPrivateKey: " + encryptionPrivateKey);
            staticLogger.debug("getEncryptionPublicKey: " + encryptionPublicKey);
            staticLogger.debug("getPublicEncryptionKeyId(): " + publicEncryptionKeyId);
            staticLogger.debug("getSignaturePrivateKey(): " + signaturePrivateKey);
            staticLogger.debug("getSignaturePublicKey(): " + signaturePublicKey);
            staticLogger.debug("getPublicSignatureKeyId(): " + publicSignatureKeyId);
            staticLogger.debug("+++++++++++++ end");

            staticLogger.debug("Read keys");

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

                // Create an entry in the publicKeyToIdentityMap
                staticLogger.debug("Looking for entry in helperPublicEncryptionKeyToPublicKeyIdMap for key: "
                        + recoveredHelperId.getPublicEncryptionKey());
            }

            staticLogger.debug("Read helper statuses: count: " + helperIds.size());
            for (DeRecIdentity helperId : helperIds) {
                staticLogger.debug("Helper Id: " + helperId.getName() + ", contact: " + helperId.getContact() + ", "
                        + "address: " + helperId.getAddress());
                staticLogger.debug(" - with pairing status: " + recoveredPairingStatuses.get(helperId));
            }

            staticLogger.debug("Calling newSecret with idBytes " + idBytes);
            staticLogger.debug("desc: " + description);

            // Now that we have read the details of the secret and the associated helpers, create a new secret
            // using this information
            SecretImpl secret =
                    new SecretImpl(new DeRecSecret.Id(idBytes), description, null, new ArrayList<>(), false);
            staticLogger.debug("Created new secret");

            // Add helpers to the newly created secret
            secret.processAddHelpersAsync(helperIds, false);
            staticLogger.debug("Added helper ids without pairing to the secret");

            for (DeRecIdentity helperId : helperIds) {
                HelperStatusImpl helperStatus = (HelperStatusImpl) secret.getHelperStatusById(helperId);
                if (helperStatus.getStatus() == DeRecPairingStatus.PairingStatus.NONE) {
                    staticLogger.debug("Setting helper status of "
                            + helperStatus.getId().getName() + " to " + recoveredPairingStatuses.get(helperId));
                    helperStatus.setStatus(recoveredPairingStatuses.get(helperId));
                }
            }

            // Add versions to the newly created secret
            VersionImpl version = new VersionImpl(secret, protectedValue, versionNumber);
            staticLogger.debug("Created new version");
            byte[] v1pv = version.getProtectedValue();
            staticLogger.debug("v1pv: size " + v1pv.length);
            staticLogger.debug("v1pv: str " + new String(v1pv));

            secret.addVersion(versionNumber, version);
            staticLogger.debug("Added version as version-" + versionNumber);

            secret.libId = new LibIdentity(
                    LibState.getInstance().getMeSharer().getName(),
                    LibState.getInstance().getMeSharer().getContact(),
                    LibState.getInstance().getMeSharer().getAddress(),
                    encryptionPrivateKey,
                    encryptionPublicKey,
                    signaturePrivateKey,
                    signaturePublicKey,
                    publicEncryptionKeyId,
                    publicSignatureKeyId);

            staticLogger.debug("Updated keys in Libstate");

            staticLogger.debug("######################################");
            staticLogger.debug("RECOVERY DONE for version: " + versionNumber);
            staticLogger.debug("######################################");
            staticLogger.debug("Recovered description " + secret.getDescription());
            staticLogger.debug("Recovered versions size " + secret.getVersions().size());

            // Add this secret to the recoveredState
            recoveredState.addSecret(secret);
        } catch (Exception ex) {
            staticLogger.error("Exception in parseSecretMessage", ex);
        }
    }

    /**
     * Periodic secret processing. Sends shares and verification requests to helpers.
     */
    public void periodicWorkForSecret() {
        logger.debug("Processing secret: " + getSecretId() + " has #versions = "
                + getVersions().size());
        NavigableMap<Integer, VersionImpl> versions = (NavigableMap<Integer, VersionImpl>) getVersions();
        if (isRecovering()) {
            LibState.getInstance().getMeSharer().getRecoveryContext().evaluateAndSendGetShareRequests(getSecretId());
        } else {
            List<Integer> versionsNumbersList = getVersions().keySet().stream().toList();
            for (int versionNumber : versionsNumbersList) {
                VersionImpl version = versions.get(versionNumber);
                version.sendSharesToPairedHelpers();
                version.sendVerificationRequestsToPairedHelpers();
            }

            if (!versionsToCleanupFromHelpers.isEmpty()) {
                logger.debug("versionsToCleanupFromHelpers is not empty");
                for (HelperStatusImpl helperStatus : versionsToCleanupFromHelpers.keySet()) {
                    List<Integer> keepList = versionsToCleanupFromHelpers.get(helperStatus);
                    logger.debug("KeepList " + keepList);
                    for (Integer v : keepList) {
                        logger.debug("Keeplist item: " + v);
                    }

                    Derecmessage.DeRecMessage deRecMessage = createStoreShareRequestMessageWithoutShare(
                            libId.getMyId(), helperStatus.getId(), id, keepList);
                    byte[] msgBytes = getPackagedBytes(
                            helperStatus.getId().getPublicEncryptionKeyId(),
                            deRecMessage.toByteArray(),
                            true,
                            id,
                            helperStatus.getId(),
                            true);
                    logger.debug(
                            "Finally sending the StoreShareRequestMessageWithoutShare - empty share with keeplist to "
                                    + helperStatus.getId().getName() + ", keepList = " + keepList);
                    sendHttpRequest(helperStatus.getId().getAddress(), msgBytes);
                    logger.debug(
                            "After sendHttpRequest after StoreShareRequestMessageWithoutShare - empty share with keeplist"
                                    + helperStatus.getId().getName() + ", keepList = " + keepList);
                }
                versionsToCleanupFromHelpers = new HashMap();
            }
        }
    }

    public LibIdentity getLibId() {
        return libId;
    }
}
