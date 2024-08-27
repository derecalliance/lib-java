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

package org.derecalliance.derec.lib.impl;

import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.impl.commands.PeriodicWorkCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PeriodicTaskRunner {
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public void startProcessing() {
        final Runnable task = new Runnable() {
            public void run() {
                // Enqueue this message to the command queue
                PeriodicWorkCommand command = new PeriodicWorkCommand(Instant.now());
                LibState.getInstance().getCommandQueue().add(command);
            }
        };

        // Schedule the task to run every 1 second after an initial delay of 0 seconds
        scheduler.scheduleAtFixedRate(task, 0, 1, TimeUnit.SECONDS);
    }

    public static void processPeriodicWork(Instant instant) {
        Logger staticLogger = LoggerFactory.getLogger(PeriodicTaskRunner.class.getName());

        if (LibState.getInstance().getMeSharer() == null) {
            return;
        }
        try {
            for (DeRecSecret derecsecret : LibState.getInstance().getMeSharer().getSecrets()) {
                staticLogger.info("About to call periodicWorkForSecret");
                ((SecretImpl) derecsecret).periodicWorkForSecret();
            }
        } catch (Exception ex) {
            staticLogger.error("Exception in periodic task runner", ex);
        }
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
