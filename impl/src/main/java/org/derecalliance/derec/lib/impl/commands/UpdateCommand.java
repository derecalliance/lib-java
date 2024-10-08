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
