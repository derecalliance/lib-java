package org.derecalliance.derec.lib.impl.commands;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.SecretImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RemoveHelpersCommand<T extends DeRecHelperStatus> implements Command {
    private final List<? extends DeRecIdentity> helperIds;
    private final SecretImpl secret;
    private final HashMap<DeRecIdentity, CompletableFuture<T>> futures;

    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public RemoveHelpersCommand(SecretImpl secret, List<? extends DeRecIdentity> helperIds) {
        this.secret = secret;
        this.helperIds = helperIds;
        this.futures = new HashMap<>();
        for (DeRecIdentity helperId : helperIds) {
            this.futures.put(helperId, new CompletableFuture<>());
        }
    }

    @Override
    public void execute() {
        List<T> helperStatuses = (List<T>) secret.processRemoveHelpersAsync(helperIds);

        for (T helperStatus : helperStatuses) {
            try {
                logger.debug("Remove Helper: Completing future for helper: "
                        + helperStatus.getId().getName());
                futures.get(helperStatus.getId()).complete(helperStatus);
            } catch (Exception ex) {
                logger.error("Exception in RemoveHelpersCommand: ", ex);
                futures.get(helperStatus.getId()).completeExceptionally(ex);
            }
        }
    }

    public List<CompletableFuture<T>> getFuture() {
        return futures.values().stream().toList();
    }
}
