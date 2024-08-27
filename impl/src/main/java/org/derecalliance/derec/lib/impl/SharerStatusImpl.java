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

import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.derecalliance.derec.lib.api.DeRecPairingStatus;

public class SharerStatusImpl implements DeRecHelper.SharerStatus {
    DeRecIdentity sharerId;
    DeRecPairingStatus.PairingStatus pairingStatus;
    boolean isRecovering;

    public SharerStatusImpl(DeRecIdentity sharerId) {
        this.sharerId = sharerId;
        this.pairingStatus = DeRecHelper.SharerStatus.PairingStatus.NONE;
        this.isRecovering = false;
    }

    @Override
    public DeRecIdentity getId() {
        return sharerId;
    }

    @Override
    public DeRecPairingStatus.PairingStatus getStatus() {
        return pairingStatus;
    }

    public void setPairingStatus(PairingStatus pairingStatus) {
        this.pairingStatus = pairingStatus;
    }

    @Override
    public boolean isRecovering() {
        return isRecovering;
    }

    public void setRecovering(boolean recovering) {
        isRecovering = recovering;
    }
}
