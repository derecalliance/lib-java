package org.derecalliance.derec.lib.impl.commands;

import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.ProtobufHttpServer;

public class MessageReceivedCommand implements Command {
    private final byte[] msgBytes;

    public MessageReceivedCommand(byte[] msgBytes) {
        this.msgBytes = msgBytes;
    }

    @Override
    public void execute() {
        ProtobufHttpServer.processReceivedMesssage(msgBytes);
    }
}
