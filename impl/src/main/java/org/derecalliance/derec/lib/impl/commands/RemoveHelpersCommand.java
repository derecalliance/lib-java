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
