package org.derecalliance.derec.lib.impl;

import java.util.Optional;
import org.derecalliance.derec.lib.api.DeRecHelperStatus;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.lib.api.DeRecStatusNotification;
import org.derecalliance.derec.lib.api.DeRecVersion;

public class StatusNotificationImpl implements DeRecStatusNotification {
    NotificationType type;
    NotificationSeverity severity;
    String message;
    DeRecSecret secret;
    DeRecVersion version;
    DeRecHelperStatus helperStatus;

    public StatusNotificationImpl(
            NotificationType type,
            NotificationSeverity severity,
            String message,
            DeRecSecret secret,
            DeRecVersion version,
            DeRecHelperStatus helperStatus) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.secret = secret;
        this.version = version;
        this.helperStatus = helperStatus;
    }

    @Override
    public NotificationType getType() {
        return type;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public Optional<DeRecVersion> getVersion() {
        return Optional.ofNullable(version);
    }

    @Override
    public Optional<DeRecHelperStatus> getHelper() {
        return Optional.ofNullable(helperStatus);
    }

    @Override
    public DeRecSecret getSecret() {
        return secret;
    }

    @Override
    public NotificationSeverity getSeverity() {
        return severity;
    }
}
