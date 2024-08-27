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

import java.util.concurrent.BlockingQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CommandProcessor implements Runnable {
    private final BlockingQueue<Command> queue;

    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public CommandProcessor(BlockingQueue<Command> queue) {
        this.queue = queue;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Command command = queue.take();
                logger.debug("Got command out of the queue: " + command);
                command.execute();
                logger.debug("Executed command: " + command + "\n---------------------\n");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

//// Start the processor in a thread
// BlockingQueue<Command> commandQueue = new LinkedBlockingQueue<>();
// Thread processorThread = new Thread(new CommandProcessor(commandQueue));
// processorThread.start();
