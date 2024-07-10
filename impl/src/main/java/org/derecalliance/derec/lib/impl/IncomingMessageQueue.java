package org.derecalliance.derec.lib.impl;

import java.util.concurrent.ConcurrentLinkedQueue;
import org.derecalliance.derec.protobuf.Derecmessage;

public class IncomingMessageQueue {
    private static final ConcurrentLinkedQueue<Derecmessage.DeRecMessage> queue = new ConcurrentLinkedQueue<>();

    public void addRequest(Derecmessage.DeRecMessage message) {
        queue.add(message);
    }

    public Derecmessage.DeRecMessage getNextRequest() {
        return queue.poll(); // This retrieves and removes the head of the queue, or returns null if empty
    }
}
