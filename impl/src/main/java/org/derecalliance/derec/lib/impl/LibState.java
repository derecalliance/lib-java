package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import org.derecalliance.derec.crypto.DerecCryptoImpl;
import org.derecalliance.derec.lib.api.*;
// import org.derecalliance.derec.crypto.DerecCryptoImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// import src.DerecCryptoImpl;

public class LibState {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());
    final double minPercentOfSharesForConfirmation = 0.5;
    final int minNumberOfHelpersForSendingShares = 2;
    final int minNumberOfHelpersForRecovery = 2;
    final int minNumberOfHelpersForConfirmingShareReceipt = 3;
    public final int thresholdToMarkHelperRefused = 20;
    public final int thresholdToMarkHelperFailed = 60;
    final boolean useRealCryptoLib = true; // TODO: remove this (useCryptoLib)
    private DerecCryptoImpl derecCryptoImpl = new DerecCryptoImpl();

    ProtobufHttpServer hServer = null;
    private static final LibState instance = new LibState();
    //    private HashMap<DeRecSecret.Id, Secret> secrets = new HashMap<>();
    private final IncomingMessageQueue incomingMessageQueue = new IncomingMessageQueue();

    //    private HashMap<Integer, String> myPublicKeys = new HashMap<>();
    private long myNonce;
    //    private boolean isRecovering = false;

    //    LibIdentity myHelperAndSharerId = null;
    SharerImpl meSharer;
    HelperImpl meHelper;

    // maps sender and receiver sha-384 hashes from incoming messages to sender and receiver DeRecIdentities
    public HashMap<ByteString, HashMap<DeRecSecret.Id, DeRecIdentity>> messageHashAndSecretIdToIdentityMap =
            new HashMap();
    public HashMap<Integer, LibIdentity> publicKeyIdToLibIdentityMap = new HashMap();

    public void registerMessageHashAndSecretIdToIdentity(
            ByteString messageHash, DeRecSecret.Id secretId, DeRecIdentity deRecIdentity) {
        if (messageHashAndSecretIdToIdentityMap.get(messageHash) == null) {
            messageHashAndSecretIdToIdentityMap.put(messageHash, new HashMap<>());
        }
        messageHashAndSecretIdToIdentityMap.get(messageHash).put(secretId, deRecIdentity);
        printMessageHashToIdentityMap();
    }

    public DeRecIdentity queryMessageHashAndSecretIdToIdentity(ByteString messageHash, DeRecSecret.Id secretId) {
        try {
            return messageHashAndSecretIdToIdentityMap.get(messageHash).get(secretId);
        } catch (Exception ex) {
            logger.error("No entry in messageHashAndSecretIdToIdentityMap for Message hash: " + messageHash
                    + ", Secret.Id: " + secretId);
            printMessageHashToIdentityMap();
            return null;
        }
    }

    public void printMessageHashToIdentityMap() {
        logger.debug("printMessageHashToIdentityMap");
        for (var hashEntry : messageHashAndSecretIdToIdentityMap.entrySet()) {
            for (var secretEntry : hashEntry.getValue().entrySet()) {
                logger.debug("Key: "
                        + Base64.getEncoder().encodeToString(hashEntry.getKey().toByteArray()) + " -> Secret: "
                        + (secretEntry.getKey() == null
                                ? "null"
                                : secretEntry.getKey().toString()) + " -> " + secretEntry.getValue());
            }
        }
        logger.debug("---- End of printMessageHashToIdentityMap ----");
    }

    public void printPublicKeyIdToIdentityMap() {
        logger.debug("printPublicKeyIdToIdentityMap");
        for (Integer key : publicKeyIdToLibIdentityMap.keySet()) {
            logger.debug("Public Key ID: " + key + " -> " + publicKeyIdToLibIdentityMap.get(key));
        }
        logger.debug("---- End of printPublicKeyIdToIdentityMap ----");
    }

    public void registerPublicKeyId(Integer publicKeyId, LibIdentity libIdentity) {
        logger.debug("In registerPublicKeyId, before:");
        printPublicKeyIdToIdentityMap();
        publicKeyIdToLibIdentityMap.put(publicKeyId, libIdentity);
        logger.debug("In registerPublicKeyId, after:");
        printPublicKeyIdToIdentityMap();
    }

    // private constructor to avoid client applications using the constructor
    private LibState() {}

    public static LibState getInstance() {
        return instance;
    }

    public double getMinPercentOfSharesForConfirmation() {
        return minPercentOfSharesForConfirmation;
    }

    public int getMinNumberOfHelpersForSendingShares() {
        return minNumberOfHelpersForSendingShares;
    }

    public int getMinNumberOfHelpersForConfirmingShareReceipt() {
        return minNumberOfHelpersForConfirmingShareReceipt;
    }

    public int getMinNumberOfHelpersForRecovery() {
        return minNumberOfHelpersForRecovery;
    }

    boolean httpServerStarted = false;

    BlockingQueue<Command> commandQueue = new LinkedBlockingQueue<>();

    BlockingQueue<Command> getCommandQueue() {
        return commandQueue;
    }

    //    public void cryptoMain() {
    //        DerecCryptoImpl cryptoImpl = new DerecCryptoImpl();
    //
    //        byte[] id = "some_id".getBytes();
    //        byte[] secret = "top_secret".getBytes();
    //
    //        List<byte[]> shares = cryptoImpl.share(id, 0, secret, 5, 3);
    //        byte[] recovered = cryptoImpl.recover(id, 0, shares);
    //
    //        String recovered_value = new String(recovered, StandardCharsets.UTF_8);
    //        assert(recovered_value.equals("top_secret"));
    //        logger.debug(recovered_value);
    //
    //        Object[] enc_key = cryptoImpl.encryptionKeyGen();
    //        byte[] alice_ek = (byte[]) enc_key[0];
    //        byte[] alice_dk = (byte[]) enc_key[1];
    //
    //        Object[] sign_key = cryptoImpl.signatureKeyGen();
    //        byte[] alice_vk = (byte[]) sign_key[0];
    //        byte[] alice_sk = (byte[]) sign_key[1];
    //
    //        enc_key = cryptoImpl.encryptionKeyGen();
    //        byte[] bob_ek = (byte[]) enc_key[0];
    //        byte[] bob_dk = (byte[]) enc_key[1];
    //
    //        sign_key = cryptoImpl.signatureKeyGen();
    //        byte[] bob_vk = (byte[]) sign_key[0];
    //        byte[] bob_sk = (byte[]) sign_key[1];
    //
    //
    //        byte[] ciphertext = cryptoImpl.signThenEncrypt(secret, alice_sk, bob_ek);
    //        byte[] plaintext = cryptoImpl.decryptThenVerify(ciphertext, alice_vk, bob_dk);
    //        recovered_value = new String(recovered, StandardCharsets.UTF_8);
    //        assert(recovered_value.equals("top_secret"));
    //        logger.debug(recovered_value);
    //    }
    public void init(String contact, String address) {
        //        cryptoMain();

        logger.debug("Debug log");
        logger.info("Info log");
        logger.trace("Trace log");
        logger.error("Error log");
        if (!httpServerStarted) {
            try {
                startHttpServer(new URI(address));
                httpServerStarted = true;
                // Start the processor in a thread
                Thread processorThread = new Thread(new CommandProcessor(commandQueue));
                processorThread.start();

                if (getMeSharer() != null) {
                    logger.debug("Init starting periodic task runner for the sharer");
                    PeriodicTaskRunner runner = new PeriodicTaskRunner();
                    runner.startProcessing();
                }
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void startHttpServer(URI address) {
        try {
            if (hServer == null) {
                hServer = new ProtobufHttpServer(address);
            }
        } catch (Exception ex) {
            logger.error("Could not start http server\n", ex);
        }
    }

    //    public void addSecret(Secret secret) {
    //        secrets.put(secret.getSecretId(), secret);
    //    }
    //    public HashMap<DeRecSecret.Id, Secret> getSecrets() {
    //        return secrets;
    //    }
    //    public Secret getSecret(DeRecSecret.Id id) {
    //        return secrets.get(id);
    //    }

    //    public void deleteSecret(Secret secret) {
    //        secrets.remove(secret.getSecretId());
    //    }

    public IncomingMessageQueue getIncomingMessageQueue() {
        return incomingMessageQueue;
    }

    public synchronized long getMyNonce() {
        return myNonce;
    }

    public synchronized void setMyNonce(long myNonce) {
        this.myNonce = myNonce;
    }

    //    public synchronized boolean isRecovering() {
    //        return isRecovering;
    //    }

    //    public synchronized void setRecovering(boolean recovering) {
    //        isRecovering = recovering;
    //    }

    public synchronized SharerImpl getMeSharer() {
        return meSharer;
    }

    public synchronized void setMeSharer(SharerImpl meSharer) {
        this.meSharer = meSharer;
    }

    public synchronized HelperImpl getMeHelper() {
        return meHelper;
    }

    public synchronized void setMeHelper(HelperImpl meHelper) {
        this.meHelper = meHelper;
    }

    //    public synchronized void setMyHelperAndSharerId(LibIdentity libIdentity) {
    //        this.myHelperAndSharerId = libIdentity;
    //    }

    public DerecCryptoImpl getDerecCryptoImpl() {
        return derecCryptoImpl;
    }
}
