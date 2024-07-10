package org.derecalliance.derec.lib.impl;



import org.derecalliance.derec.lib.api.*;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
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
//import org.derecalliance.derec.lib.LibIdentity;
//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Version;
import org.derecalliance.derec.lib.impl.commands.NewSecretCommand;
import org.derecalliance.derec.lib.impl.commands.PeriodicWorkCommand;
import org.derecalliance.derec.protobuf.Parameterrange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SharerImpl implements DeRecSharer {
//    LibIdentity myHelperAndSharerId;
    String name;
    String contact;
    String address;

    ConcurrentHashMap<DeRecSecret.Id, SecretImpl> secretsMap;
        //    PairingContext pairingContext;
        Parameterrange.ParameterRange parameterRange;
        //    DeRecIdentity mySharerId;
//        LibIdentity myLibId;

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
//            // If a LibIdentity is already created for my role as a Helper, reuse that LibIdentity, otherwise create a
//            // new LibIdentity
//            if (LibState.getInstance().myHelperAndSharerId == null) {
//                logger.debug("SharerImpl: Creating new LibIdentity as a Sharer for " + name);
//                myLibId = new LibIdentity(name, uri, uri);
////                LibState.getInstance().myHelperAndSharerId = myLibId;
//
//            } else {
//                logger.debug("SharerImpl: Reusing Helper's LibIdentity as a Sharer for " + name);
//                myLibId = LibState.getInstance().myHelperAndSharerId;
//            }

        // Register in the messageHashAndSecretIdToIdentityMap table for self id.
        // Since we are a sharer, but we don't have a secret id yet, hence register with a null secret id
//            LibState.getInstance().messageHashToIdentityMap.put(
//                    ByteString.copyFrom(myLibId.getMyId().getPublicEncryptionKeyDigest()), myLibId.getMyId());
//        // TODO-PerSecretKeys -> move this to when a secret is created in a sharer
//        LibState.getInstance().registerMessageHashAndSecretIdToIdentity(
//                ByteString.copyFrom(myLibId.getMyId().getPublicEncryptionKeyDigest()), null, myLibId.getMyId());
//            logger.debug("Added myself (Sharer) " + name + " to messageHashToIdentityMap");

//        LibState.getInstance().printMessageHashToIdentityMap();

            LibState.getInstance().setMeSharer(this);
            recoveryContext = new RecoveryContext();
            recoveredState = new RecoveredState();

            listener = notification -> {};
            LibState.getInstance().init(contact, address);
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
        public DeRecSecret newSecret(String description, byte[] bytesToProtect, boolean recovery) {
            NewSecretCommand command = new NewSecretCommand(this, description, bytesToProtect, recovery);
            LibState.getInstance().getCommandQueue().add(command);
            try {
                return command.getFuture().get();
            } catch(Exception ex) {
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
            logger.debug("\n in getSecret for secretId: " +  Base64.getEncoder().encodeToString(secretId.getBytes()));
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

//        public LibIdentity getMyLibId() {
//            return myLibId;
//        }

        public void installRecoveredSecret(SecretImpl secret) {
            secretsMap.put(secret.getSecretId(), secret);
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
        public RecoveredState getRecoveredState() { return recoveredState; }

    // Based on the information stored in recoveredState, update the current working state
    public void recoveryComplete(DeRecSecret.Id recoverySecretId) {
        logger.debug("In recoveryComplete");

        for (SecretImpl recoveredSecret : recoveredState.getSecretsMap().values()) {
            for (DeRecHelperStatus helperStatus : recoveredSecret.getHelperStatuses()) {
//                // Update the publicKeyId <-> identity map
//                DeRecIdentity recoveredHelperId = helperStatus.getId();
//                if (recoveredState.getHelperPublicEncryptionKeyToPublicKeyIdMap().containsKey(recoveredHelperId.getPublicEncryptionKey())) {
//                    LibState.getInstance().registerPublicKeyId(
//                            recoveredState.getHelperPublicEncryptionKeyToPublicKeyIdMap().get(recoveredHelperId.getPublicEncryptionKey()),
//                            recoveredHelperId);
//                    logger.debug("recoveryComplete: Added entry to publicKeyIdToIdentityMap for " + recoveredHelperId.getName() + ", " +
//                            "publicKeyId = "
//                            + recoveredState.getHelperPublicEncryptionKeyToPublicKeyIdMap().get(recoveredHelperId.getPublicEncryptionKey()));
//                    LibState.getInstance().printPublicKeyIdToIdentityMap();
//                } else {
//                    logger.debug("recoveryComplete: Entry not found for key: " + recoveredHelperId.getPublicEncryptionKey());
//                }


                // Install the original helpers' messageHashes
                logger.debug("During recovery, installing in registerMessageHashAndSecretIdToIdentity: " + helperStatus.getId().getName());
                LibState.getInstance().registerMessageHashAndSecretIdToIdentity( ByteString.copyFrom(helperStatus.getId().getPublicEncryptionKeyDigest()), recoveredSecret.getSecretId(), helperStatus.getId());
            }


            // TODO-PerSecretKeys Move this in the loop above, and call LibState.getInstance().registerMessageHashAndSecretIdToIdentity();

            // Set my DeRec identity and keys from the recovered information
//            LibState.getInstance().getMeSharer().getMyLibId().setVariables(
//                    recoveredState.getSharerIdentity().getMyId().getName(),
//                    recoveredState.getSharerIdentity().getMyId().getContact(),
//                    recoveredState.getSharerIdentity().getMyId().getAddress(),
//                    recoveredState.getSharerIdentity().getEncryptionPrivateKey(),
//                    recoveredState.getSharerIdentity().getEncryptionPublicKey(),
//                    recoveredState.getSharerIdentity().getSignaturePrivateKey(),
//                    recoveredState.getSharerIdentity().getSignaturePublicKey(),
//                    recoveredState.getSharerIdentity().getPublicEncryptionKeyId(),
//                    recoveredState.getSharerIdentity().getPublicSignatureKeyId());

            // Install this secret's libIdentity in the publicKeyIdToLibIdentityMap
            logger.debug("Installing secret's id in publicKeyIdToLibIdentityMap");
            LibState.getInstance().registerPublicKeyId(recoveredSecret.getLibId().getPublicEncryptionKeyId(), recoveredSecret.getLibId());

            // Install own libIdentity in the messageHashAndSecretIdToIdentityMap
            logger.debug("During recovery, installing own identity in registerMessageHashAndSecretIdToIdentity: " + recoveredSecret.getLibId().getMyId().getName());
            LibState.getInstance().registerMessageHashAndSecretIdToIdentity( ByteString.copyFrom(recoveredSecret.getLibId().getMyId().getPublicEncryptionKeyDigest()), recoveredSecret.getSecretId(), recoveredSecret.getLibId().getMyId());

        }





        // Install the secrets and calculate the shares for the secrets
        for (SecretImpl recoveredSecret : recoveredState.getSecretsMap().values()) {
            // Install secret
            LibState.getInstance().getMeSharer().installRecoveredSecret(recoveredSecret);
            logger.debug("Installed secret " + recoveredSecret.getDescription());

            // Recalculate the shares for all versions now
            DeRecSecret installedSecret = LibState.getInstance().getMeSharer().getSecret(recoveredSecret.getSecretId());
            logger.debug("After installing, found secret: " + installedSecret.getDescription());
            for (DeRecVersion deRecVersion: installedSecret.getVersions().values().stream().toList()) {
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

    public void removeSecret(DeRecSecret.Id secretId) {
//            SecretImpl secretToRemove = (SecretImpl) getSecret(secretId);
            secretsMap.remove(secretId);
        }

        public void deliverNotification(StatusNotificationImpl notification) {
            listener.accept(notification);
        }
        public void deliverNotification(DeRecStatusNotification.NotificationType type,
                                        DeRecStatusNotification.NotificationSeverity severity, String message,
                                        SecretImpl secret, VersionImpl version, HelperStatusImpl helperStatus) {
            StatusNotificationImpl notification = new StatusNotificationImpl(type, severity, message, secret, version,
                    helperStatus);
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


