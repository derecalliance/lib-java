package org.derecalliance.derec.lib.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

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
//BlockingQueue<Command> commandQueue = new LinkedBlockingQueue<>();
//Thread processorThread = new Thread(new CommandProcessor(commandQueue));
//processorThread.start();
