package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.*;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.function.Consumer;

import com.google.protobuf.ByteString;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.api.DeRecSharer;
import org.derecalliance.derec.lib.api.DeRecStatusNotification;
import org.derecalliance.derec.protobuf.Parameterrange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SharerImpl implements DeRecSharer {

    ConcurrentHashMap<DeRecSecret.Id, SecretImpl> secretsMap;
    Parameterrange.ParameterRange parameterRange;
    LibIdentity myLibId;
    Consumer<DeRecStatusNotification> listener;
    RecoveryContext recoveryContext;
    RecoveredState recoveredState;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public SharerImpl(String name, String uri) {
        secretsMap = new ConcurrentHashMap<>();
        parameterRange = Parameterrange.ParameterRange.newBuilder().build();
        // If a LibIdentity is already created for my role as a Helper, reuse that LibIdentity, otherwise create a
        // new LibIdentity
        if (LibState.getInstance().myHelperAndSharerId == null) {
            logger.debug("SharerImpl: Creating new LibIdentity as a Sharer for " + name);
            myLibId = new LibIdentity(name, uri, uri);
            LibState.getInstance().myHelperAndSharerId = myLibId;
        } else {
            logger.debug("SharerImpl: Reusing Helper's LibIdentity as a Sharer for " + name);
            myLibId = LibState.getInstance().myHelperAndSharerId;
        }
        LibState.getInstance().messageHashToIdentityMap.put(
                ByteString.copyFrom(myLibId.getMyId().getPublicEncryptionKeyDigest()), myLibId.getMyId());
        logger.debug("Added myself (Sharer) " + name + " to messageHashToIdentityMap");

        LibState.getInstance().printMessageHashToIdentityMap();

        LibState.getInstance().setMeSharer(this);
        recoveryContext = new RecoveryContext();
        recoveredState = new RecoveredState();

        listener = notification -> {
        };
        LibState.getInstance().init(uri);
    }

    @Override
    public DeRecSecret newSecret(String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public DeRecSecret newSecret(DeRecSecret.Id secretId, String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public DeRecSecret newSecret(String description,
                                 byte[] bytesToProtect, boolean recovery) {
        var secret = new SecretImpl(description, bytesToProtect, recovery);
        synchronized (secretsMap) {
            secretsMap.put(secret.getSecretId(), secret);
        }
        printSecretsMap();
        return secret;
    }

    @Override
    public DeRecSecret newSecret(DeRecSecret.Id secretId, String description, byte[] bytesToProtect, boolean recovery) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public DeRecSecret getSecret(DeRecSecret.Id secretId) {
        logger.debug("\n in getSecret for secretId: " + Base64.getEncoder().encodeToString(secretId.getBytes()));
        logger.debug("Secret map is:");
        printSecretsMap();
        return secretsMap.get(secretId);
    }

    @Override
    public List<? extends DeRecSecret> getSecrets() {
        return (secretsMap.values().stream().toList());
    }

    @Override
    public Future<Map<DeRecSecret.Id, List<Integer>>> getSecretIdsAsync(DeRecIdentity helper) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public DeRecSecret recoverSecret(DeRecSecret.Id secretId, int version, List<? extends DeRecIdentity> helpers) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public void setListener(Consumer<DeRecStatusNotification> listener) {
        this.listener = listener;
    }

    Parameterrange.ParameterRange getParameterRange() {
        return parameterRange;
    }

    public LibIdentity getMyLibId() {
        return myLibId;
    }

    void printSecretsMap() {
        logger.debug("Secrets Map");
        for (DeRecSecret.Id secretId : secretsMap.keySet()) {
            logger.debug("Key: " + Base64.getEncoder().encodeToString(secretId.getBytes()) + " -> " + secretsMap.get(secretId).getDescription());
        }
    }

    public RecoveryContext getRecoveryContext() {
        return recoveryContext;
    }

    public RecoveredState getRecoveredState() {
        return recoveredState;
    }

    /**
     * Used in recovery to add the recovered secret to secretsMap
     *
     * @param secret Recovered secret
     */
    public void installRecoveredSecret(SecretImpl secret) {
        secretsMap.put(secret.getSecretId(), secret);
    }

    @Override
    public void recoveryComplete(DeRecSecret.Id recoverySecretId) {
        // Based on the information stored in recoveredState, update the current working state
        logger.debug("In recoveryComplete");

        for (SecretImpl recoveredSecret : recoveredState.getSecretsMap().values()) {
            for (DeRecHelperStatus helperStatus : recoveredSecret.getHelperStatuses()) {
                // Update the publicKeyId -> identity map
                DeRecIdentity recoveredHelperId = helperStatus.getId();
                if (recoveredState.getHelperPublicEncryptionKeyToPublicKeyIdMap().containsKey(recoveredHelperId.getPublicEncryptionKey())) {
                    LibState.getInstance().registerPublicKeyId(
                            recoveredState.getHelperPublicEncryptionKeyToPublicKeyIdMap().get(recoveredHelperId.getPublicEncryptionKey()),
                            recoveredHelperId);
                    logger.debug("recoveryComplete: Added entry to publicKeyIdToIdentityMap for " + recoveredHelperId.getName() + ", " +
                            "publicKeyId = "
                            + recoveredState.getHelperPublicEncryptionKeyToPublicKeyIdMap().get(recoveredHelperId.getPublicEncryptionKey()));
                    LibState.getInstance().printPublicKeyIdToIdentityMap();
                } else {
                    logger.debug("recoveryComplete: Entry not found for key: " + recoveredHelperId.getPublicEncryptionKey());
                }
            }
        }

        // Set my DeRec identity and keys from the recovered information
        LibState.getInstance().getMeSharer().getMyLibId().setVariables(
                recoveredState.getSharerIdentity().getMyId().getName(),
                recoveredState.getSharerIdentity().getMyId().getContact(),
                recoveredState.getSharerIdentity().getMyId().getAddress(),
                recoveredState.getSharerIdentity().getEncryptionPrivateKey(),
                recoveredState.getSharerIdentity().getEncryptionPublicKey(),
                recoveredState.getSharerIdentity().getSignaturePrivateKey(),
                recoveredState.getSharerIdentity().getSignaturePublicKey(),
                recoveredState.getSharerIdentity().getPublicEncryptionKeyId(),
                recoveredState.getSharerIdentity().getPublicSignatureKeyId());

        // Install the secrets and calculate the shares for the secrets
        for (SecretImpl recoveredSecret : recoveredState.getSecretsMap().values()) {
            // Install secret
            LibState.getInstance().getMeSharer().installRecoveredSecret(recoveredSecret);
            logger.debug("Installed secret " + recoveredSecret.getDescription());

            // Recalculate the shares for all versions now
            DeRecSecret installedSecret = LibState.getInstance().getMeSharer().getSecret(recoveredSecret.getSecretId());
            logger.debug("After installing, found secret: " + installedSecret.getDescription());
            for (DeRecVersion deRecVersion : installedSecret.getVersions().values().stream().toList()) {
                VersionImpl version = (VersionImpl) deRecVersion;
                version.createShares();
                logger.debug("Created shares for version: " + version.getVersionNumber());

            }
        }

        // Delete the dummy secret used for pairing during recovery
        DeRecSecret recoverySecret = getSecret(recoverySecretId);
        recoverySecret.close();
        logger.debug("Closed secret: " + recoverySecret.getDescription());

        printSecretsMap();
    }

    /**
     * Removes secret from secretsMap
     *
     * @param secretId Secret Id of the secret to remove
     */
    public void removeSecret(DeRecSecret.Id secretId) {
        secretsMap.remove(secretId);
    }

    /**
     * Deliver's a notification to the Sharer's application
     *
     * @param notification Notification
     */
    public void deliverNotification(StatusNotificationImpl notification) {
        listener.accept(notification);
    }

    /**
     * Delivers a notification to the Sharer's application
     *
     * @param type         Notification type
     * @param severity     Notification severity
     * @param message      Message associated with the notification
     * @param secret       Secret associated with the notification
     * @param version      Version associated with the notification
     * @param helperStatus HelperStatus associated with the notification
     */
    public void deliverNotification(DeRecStatusNotification.NotificationType type,
                                    DeRecStatusNotification.NotificationSeverity severity, String message,
                                    SecretImpl secret, VersionImpl version, HelperStatusImpl helperStatus) {
        StatusNotificationImpl notification = new StatusNotificationImpl(type, severity, message, secret, version,
                helperStatus);
        listener.accept(notification);
    }
}
