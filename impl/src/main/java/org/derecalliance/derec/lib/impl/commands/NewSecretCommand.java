package org.derecalliance.derec.lib.impl.commands;

import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.SecretImpl;
import org.derecalliance.derec.lib.impl.SharerImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class NewSecretCommand implements Command {
    private final String description;
    private final byte[] bytesToProtect;
    private final boolean recovery;
    private final SharerImpl sharer;
    private final CompletableFuture<DeRecSecret> future;

    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public NewSecretCommand(SharerImpl sharer, String description, byte[] bytesToProtect, boolean recovery) {
        this.sharer = sharer;
        this.description = description;
        this.bytesToProtect = bytesToProtect;
        this.recovery = recovery;
        this.future = new CompletableFuture<>();
    }

    @Override
    public void execute() {
        SecretImpl secret = sharer.processNewSecret(description, bytesToProtect, recovery);
        try {
            future.complete(secret);
        } catch (Exception ex) {
            logger.error("Exception in NewSecretCommand: ", ex);
            future.completeExceptionally(ex);
        }
    }

    public CompletableFuture<DeRecSecret> getFuture() {
        return future;
    }
}
