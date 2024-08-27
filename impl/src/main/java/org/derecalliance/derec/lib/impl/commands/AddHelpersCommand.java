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

public class AddHelpersCommand<T extends DeRecHelperStatus> implements Command {
    private final List<? extends DeRecIdentity> helperIds;
    private final SecretImpl secret;
    private final boolean isSync;
    private final HashMap<String, CompletableFuture<T>> futures; // Helper's publicEncryption key -> future map

    private List<T> helperStatuses;

    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public AddHelpersCommand(SecretImpl secret, List<? extends DeRecIdentity> helperIds, boolean isSync) {
        logger.debug("In AddHelpersCommand: secret: " + secret + ", helperIds: " + helperIds + ", isSync: " + isSync);
        this.secret = secret;
        this.helperIds = helperIds;
        this.isSync = isSync;
        this.futures = new HashMap<>();
        for (DeRecIdentity helperId : helperIds) {
            this.futures.put(helperId.getPublicEncryptionKey(), new CompletableFuture<>());
        }
    }

    @Override
    public void execute() {
        helperStatuses = (List<T>) secret.processAddHelpersAsync(helperIds, true);
        logger.debug("In AddHelpersCommand: execute, got return value as: " + helperStatuses);

        //        if (isSync) {
        //            ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        //            logger.debug("Starting 10 seconds wait before completing");
        //            scheduler.schedule(() -> futureCompletion(), 10, TimeUnit.SECONDS);
        //            scheduler.shutdown();
        //        } else {
        //            futureCompletion();
        //        }
        futureCompletion();
    }

    public void futureCompletion() {
        for (T helperStatus : helperStatuses) {
            try {
                futures.get(helperStatus.getId().getPublicEncryptionKey()).complete(helperStatus);
            } catch (Exception ex) {
                logger.error("Exception in AddHelpersCommand: ", ex);
                futures.get(helperStatus.getId()).completeExceptionally(ex);
            }
        }
    }

    public List<CompletableFuture<T>> getFutures() {
        return futures.values().stream().toList();
    }
}
