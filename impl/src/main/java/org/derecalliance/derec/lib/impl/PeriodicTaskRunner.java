package org.derecalliance.derec.lib.impl;

//import org.derecalliance.derec.api.*;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class PeriodicTaskRunner {
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public void startProcessing() {
        final Runnable task = new Runnable() {
            public void run() {
                logger.info("In run()");

//                Derecmessage.DeRecMessage deRecMessage;
//                while ((deRecMessage = LibState.getInstance().getIncomingMessageQueue().getNextRequest()) != null) {
//                    // Process the request
//                    System.out.println("Processing dequeued message");
//                    // Check if messageBodies is present and is of type SharerMessageBodies
//                    if (deRecMessage.hasMessageBodies() && deRecMessage.getMessageBodies().hasSharerMessageBodies()) {
//                        System.out.println("sharer bodies");
//                        // Iterate over each SharerMessageBody in SharerMessageBodies
//                        for (Derecmessage.DeRecMessage.SharerMessageBody sharerMessageBody : deRecMessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBodyList()) {
//                            System.out.println("one sharer body");
//                            // Check if the SharerMessageBody contains a PairRequestMessage
//                            if (sharerMessageBody.hasPairRequestMessage()) {
//                                Pair.PairRequestMessage pairRequestMessage = sharerMessageBody.getPairRequestMessage();
//                                System.out.println("Received Pair request " +
//                                        "message");
//                            } else {
//                                System.out.println("non pair request msg");
//                            }
//                        }
//                    }
//                }

                if (LibState.getInstance().getMeSharer() == null) {
                    return;
                }
                try {
                    for (DeRecSecret derecsecret:
                         LibState.getInstance().getMeSharer().getSecrets()) {
                        logger.info("About to call periodicWorkForSecret");
                         ((SecretImpl)derecsecret).periodicWorkForSecret();
                    }
                } catch (Exception ex) {
                    System.out.println("Exception in periodic task runner");
                    ex.printStackTrace();
                }
            }
        };

        // Schedule the task to run every 1 second after an initial delay of 0 seconds
        scheduler.scheduleAtFixedRate(task, 0, 1, TimeUnit.SECONDS);
    }

    public void stopProcessing() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(60, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) {
        PeriodicTaskRunner runner = new PeriodicTaskRunner();
        runner.startProcessing();

        try {
            Thread.sleep(10000); // kill after 10 seconds
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        runner.stopProcessing();
    }
}