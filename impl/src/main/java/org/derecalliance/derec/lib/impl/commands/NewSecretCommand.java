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

import java.util.concurrent.CompletableFuture;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.SecretImpl;
import org.derecalliance.derec.lib.impl.SharerImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
