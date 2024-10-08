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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.api.DeRecSharer;
import org.derecalliance.derec.lib.api.DeRecStatusNotification;
import org.derecalliance.derec.lib.impl.commands.NewSecretCommand;
import org.derecalliance.derec.protobuf.Parameterrange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SharerImpl implements DeRecSharer {
    String name;
    String contact;
    String address;
    ConcurrentHashMap<DeRecSecret.Id, SecretImpl> secretsMap;
    Parameterrange.ParameterRange parameterRange;
    Consumer<DeRecStatusNotification> listener;
    RecoveryContext recoveryContext;
    RecoveredState recoveredState;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public SharerImpl(String name, String contact, String address) {
        this.name = name;
        this.contact = contact;
        this.address = address;
        secretsMap = new ConcurrentHashMap<>();
        parameterRange = Parameterrange.ParameterRange.newBuilder().build();
        LibState.getInstance().setMeSharer(this);
        recoveryContext = new RecoveryContext();
        recoveredState = new RecoveredState();

        listener = notification -> {};
        LibState.getInstance().init(contact, address);
    }

    @Override
    public DeRecSecret newSecret(
            String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public DeRecSecret newSecret(
            DeRecSecret.Id secretId,
            String description,
            byte[] bytesToProtect,
            List<DeRecIdentity> helperIds,
            boolean recovery) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    @Override
    public DeRecSecret newSecret(String description, byte[] bytesToProtect, boolean recovery) {
        NewSecretCommand command = new NewSecretCommand(this, description, bytesToProtect, recovery);
        LibState.getInstance().getCommandQueue().add(command);
        try {
            return command.getFuture().get();
        } catch (Exception ex) {
            logger.error("Exception in newSecret.", ex);
            return null;
        }
    }

    @Override
    public DeRecSecret newSecret(DeRecSecret.Id secretId, String description, byte[] bytesToProtect, boolean recovery) {
        logger.debug("Not implemented\n");
        Thread.currentThread().getStackTrace();
        return null;
    }

    public SecretImpl processNewSecret(String description, byte[] bytesToProtect, boolean recovery) {
        var secret = new SecretImpl(description, bytesToProtect, recovery);
        synchronized (secretsMap) {
            secretsMap.put(secret.getSecretId(), secret);
        }
        printSecretsMap();
        return secret;
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

    void printSecretsMap() {
        logger.debug("Secrets Map");
        for (DeRecSecret.Id secretId : secretsMap.keySet()) {
            logger.debug("Key: " + Base64.getEncoder().encodeToString(secretId.getBytes()) + " -> "
                    + secretsMap.get(secretId).getDescription());
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
                // Install the original helpers' messageHashes
                logger.debug("During recovery, installing in registerMessageHashAndSecretIdToIdentity: "
                        + helperStatus.getId().getName());
                LibState.getInstance()
                        .registerMessageHashAndSecretIdToIdentity(
                                ByteString.copyFrom(helperStatus.getId().getPublicEncryptionKeyDigest()),
                                recoveredSecret.getSecretId(),
                                helperStatus.getId());
            }

            // Install this secret's libIdentity in the publicKeyIdToLibIdentityMap
            logger.debug("Installing secret's id in publicKeyIdToLibIdentityMap");
            LibState.getInstance()
                    .registerPublicKeyId(
                            recoveredSecret.getLibId().getPublicEncryptionKeyId(), recoveredSecret.getLibId());

            // Install own libIdentity in the messageHashAndSecretIdToIdentityMap
            logger.debug("During recovery, installing own identity in registerMessageHashAndSecretIdToIdentity: "
                    + recoveredSecret.getLibId().getMyId().getName());
            LibState.getInstance()
                    .registerMessageHashAndSecretIdToIdentity(
                            ByteString.copyFrom(
                                    recoveredSecret.getLibId().getMyId().getPublicEncryptionKeyDigest()),
                            recoveredSecret.getSecretId(),
                            recoveredSecret.getLibId().getMyId());
        }

        // Install the secrets and calculate the shares for the secrets
        for (SecretImpl recoveredSecret : recoveredState.getSecretsMap().values()) {
            // Install secret
            LibState.getInstance().getMeSharer().installRecoveredSecret(recoveredSecret);
            logger.debug("Installed secret " + recoveredSecret.getDescription());

            // Recalculate the shares for all versions now
            DeRecSecret installedSecret = LibState.getInstance().getMeSharer().getSecret(recoveredSecret.getSecretId());
            logger.debug("After installing, found secret: " + installedSecret.getDescription());
            for (DeRecVersion deRecVersion :
                    installedSecret.getVersions().values().stream().toList()) {
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
     * Delivers a notification to the Sharer's application
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
    public void deliverNotification(
            DeRecStatusNotification.NotificationType type,
            DeRecStatusNotification.NotificationSeverity severity,
            String message,
            SecretImpl secret,
            VersionImpl version,
            HelperStatusImpl helperStatus) {
        StatusNotificationImpl notification =
                new StatusNotificationImpl(type, severity, message, secret, version, helperStatus);
        listener.accept(notification);
    }

    public String getName() {
        return name;
    }

    public String getContact() {
        return contact;
    }

    public String getAddress() {
        return address;
    }
}
