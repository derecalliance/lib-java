package org.derecalliance.derec.lib.impl.commands;

import java.time.Instant;
import org.derecalliance.derec.lib.impl.Command;
import org.derecalliance.derec.lib.impl.PeriodicTaskRunner;

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
