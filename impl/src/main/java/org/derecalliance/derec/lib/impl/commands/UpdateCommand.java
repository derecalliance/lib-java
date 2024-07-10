package org.derecalliance.derec.lib.impl.commands;

import java.util.concurrent.CompletableFuture;
import org.derecalliance.derec.lib.api.DeRecVersion;
import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.SecretImpl;

public class UpdateCommand implements Command {
    private final byte[] bytesToProtect;
    private final SecretImpl secret;
    private final CompletableFuture<DeRecVersion> future;

    public UpdateCommand(SecretImpl secret, byte[] bytesToProtect) {
        this.secret = secret;
        this.bytesToProtect = bytesToProtect;
        this.future = new CompletableFuture<>();
    }

    @Override
    public void execute() {
        DeRecVersion version = secret.processUpdateAsync(bytesToProtect);
        future.complete(version);
    }

    public CompletableFuture<DeRecVersion> getFuture() {
        return future;
    }
}
