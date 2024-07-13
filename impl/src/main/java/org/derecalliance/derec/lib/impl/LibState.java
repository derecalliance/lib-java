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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LibState {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());
    final double minPercentOfSharesForConfirmation = 0.5;
    final int minNumberOfHelpersForSendingShares = 2;
    final int minNumberOfHelpersForRecovery = 2;
    final int minNumberOfHelpersForConfirmingShareReceipt = 3;
    public final int thresholdToMarkHelperRefused = 20;
    public final int thresholdToMarkHelperFailed = 60;
    private DerecCryptoImpl derecCryptoImpl = new DerecCryptoImpl();
    ProtobufHttpServer hServer = null;
    private static final LibState instance = new LibState();
    boolean httpServerStarted = false;
    BlockingQueue<Command> commandQueue = new LinkedBlockingQueue<>();
    private long myNonce;
    SharerImpl meSharer;
    HelperImpl meHelper;

    // maps sender and receiver sha-384 hashes from incoming messages to sender and receiver DeRecIdentities
    public HashMap<ByteString, HashMap<DeRecSecret.Id, DeRecIdentity>> messageHashAndSecretIdToIdentityMap =
            new HashMap();
    // Maps user's publicKeyId to DeRecIdentity. Used to decrypt messages according to the publicKeyId they are sent
    // with
    public HashMap<Integer, LibIdentity> publicKeyIdToLibIdentityMap = new HashMap();

    /**
     * Adds an element to messageHashAndSecretIdToIdentityMap
     */
    public void registerMessageHashAndSecretIdToIdentity(
            ByteString messageHash, DeRecSecret.Id secretId, DeRecIdentity deRecIdentity) {
        if (messageHashAndSecretIdToIdentityMap.get(messageHash) == null) {
            messageHashAndSecretIdToIdentityMap.put(messageHash, new HashMap<>());
        }
        messageHashAndSecretIdToIdentityMap.get(messageHash).put(secretId, deRecIdentity);
        printMessageHashToIdentityMap();
    }

    /**
     * Queries messageHashAndSecretIdToIdentityMap for a given messageHash and secretId
     *
     * @return DeRecIdentity
     */
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

    /**
     * Print routine for messageHashAndSecretIdToIdentityMap
     */
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

    /**
     * Print routine for publicKeyIdToLibIdentityMap
     */
    public void printPublicKeyIdToIdentityMap() {
        logger.debug("printPublicKeyIdToIdentityMap");
        for (Integer key : publicKeyIdToLibIdentityMap.keySet()) {
            logger.debug("Public Key ID: " + key + " -> " + publicKeyIdToLibIdentityMap.get(key));
        }
        logger.debug("---- End of printPublicKeyIdToIdentityMap ----");
    }

    /**
     * Adds an element to publicKeyIdToLibIdentityMap
     */
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

    BlockingQueue<Command> getCommandQueue() {
        return commandQueue;
    }

    /**
     * Starts the HTTP server and processing
     *
     * @param contact contact info
     * @param address address to communicate
     */
    public void init(String contact, String address) {
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

    /**
     * Starts HTTP server
     *
     * @param address address for communication
     */
    public void startHttpServer(URI address) {
        try {
            if (hServer == null) {
                hServer = new ProtobufHttpServer(address);
            }
        } catch (Exception ex) {
            logger.error("Could not start http server\n", ex);
        }
    }

    public synchronized long getMyNonce() {
        return myNonce;
    }

    public synchronized void setMyNonce(long myNonce) {
        this.myNonce = myNonce;
    }

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

    public DerecCryptoImpl getDerecCryptoImpl() {
        return derecCryptoImpl;
    }
}
