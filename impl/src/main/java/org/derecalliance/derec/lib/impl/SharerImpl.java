package org.derecalliance.derec.lib.impl;



import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.api.DeRecSharer;
import org.derecalliance.derec.lib.api.DeRecStatusNotification;

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
//import org.derecalliance.derec.lib.LibIdentity;
//import org.derecalliance.derec.lib.LibState;
//import org.derecalliance.derec.lib.Version;
import org.derecalliance.derec.protobuf.Parameterrange;


public class SharerImpl implements DeRecSharer {

            ConcurrentHashMap<DeRecSecret.Id, SecretImpl> secretsMap;
        //    PairingContext pairingContext;
        Parameterrange.ParameterRange parameterRange;
        //    DeRecIdentity mySharerId;
        LibIdentity myLibId;

        Consumer<DeRecStatusNotification> listener;

        RecoveryContext recoveryContext;

        public SharerImpl(String name, String uri) {
            secretsMap = new ConcurrentHashMap<>();
            parameterRange = Parameterrange.ParameterRange.newBuilder().build();
            // If a LibIdentity is already created for my role as a Helper, reuse that LibIdentity, otherwise create a
            // new LibIdentity
            if (LibState.getInstance().myHelperAndSharerId == null) {
                System.out.println("SharerImpl: Creating new LibIdentity as a Sharer for " + name);
                myLibId = new LibIdentity(name, uri, uri);
                LibState.getInstance().myHelperAndSharerId = myLibId;
            } else {
                System.out.println("SharerImpl: Reusing Helper's LibIdentity as a Sharer for " + name);
                myLibId = LibState.getInstance().myHelperAndSharerId;
            }
            LibState.getInstance().messageHashToIdentityMap.put(
                    ByteString.copyFrom(myLibId.getMyId().getPublicEncryptionKeyDigest()), myLibId.getMyId());
            LibState.getInstance().setMeSharer(this);
            recoveryContext = new RecoveryContext();
            listener = notification -> {};
            LibState.getInstance().init(uri);
        }

        @Override
        public DeRecSecret newSecret(String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
            System.out.println("Not implemented\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public DeRecSecret newSecret(DeRecSecret.Id secretId, String description, byte[] bytesToProtect, List<DeRecIdentity> helperIds, boolean recovery) {
            System.out.println("Not implemented\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public DeRecSecret newSecret(String description,
                                     byte[] bytesToProtect, boolean recovery) {
            var secret = new SecretImpl(description,bytesToProtect,recovery);
            synchronized (secretsMap) {
                secretsMap.put(secret.getSecretId(), secret);
            }
            printSecretsMap();
            return secret;
        }

        @Override
        public DeRecSecret newSecret(DeRecSecret.Id secretId, String description, byte[] bytesToProtect, boolean recovery) {
            System.out.println("Not implemented\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public DeRecSecret getSecret(DeRecSecret.Id secretId) {
            System.out.println("\n in getSecret for secretId: " +  Base64.getEncoder().encodeToString(secretId.getBytes()));
            System.out.println("Secret map is:");
            printSecretsMap();
            return secretsMap.get(secretId);
        }

        @Override
        public List<? extends DeRecSecret> getSecrets() {
            return (secretsMap.values().stream().toList());
        }

        @Override
        public Future<Map<DeRecSecret.Id, List<Integer>>> getSecretIdsAsync(DeRecIdentity helper) {
            System.out.println("Not implemented\n");
            Thread.currentThread().getStackTrace();
            return null;
        }

        @Override
        public DeRecSecret recoverSecret(DeRecSecret.Id secretId, int version, List<? extends DeRecIdentity> helpers) {
            System.out.println("Not implemented\n");
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
            System.out.println("Secrets Map");
            for (DeRecSecret.Id secretId : secretsMap.keySet()) {
                System.out.println("Key: " + Base64.getEncoder().encodeToString(secretId.getBytes()) + " -> " + secretsMap.get(secretId).getDescription());
            }
        }

        public RecoveryContext getRecoveryContext() {
            return recoveryContext;
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
    }
