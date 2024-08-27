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
