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
