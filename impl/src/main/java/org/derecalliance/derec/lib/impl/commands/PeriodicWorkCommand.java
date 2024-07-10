package org.derecalliance.derec.lib.impl.commands;

import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.PeriodicTaskRunner;
import org.derecalliance.derec.lib.impl.ProtobufHttpServer;

import java.time.Instant;

public class PeriodicWorkCommand implements Command {
    private final Instant instant;

    public PeriodicWorkCommand(Instant instant) {
        this.instant = instant;
    }

        @Override
    public void execute() {
        PeriodicTaskRunner.processPeriodicWork(instant);
    }
}
