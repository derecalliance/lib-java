package org.derecalliance.derec.lib.impl.commands;

import org.derecalliance.derec.lib.api.DeRecVersion;
import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.ProtobufHttpServer;
import org.derecalliance.derec.lib.impl.SecretImpl;

import java.util.concurrent.CompletableFuture;

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
