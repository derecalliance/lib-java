package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.*;
import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecSecret;

import java.util.ArrayList;
import java.util.List;

public class ShareImpl implements DeRecHelper.Share  {
    private int versionNumber;
    private DeRecHelper.SharerStatus sharerStatus;
    private DeRecSecret.Id secretId;
    private byte[] committedDeRecShareBytes;
    private boolean isConfirmed;

    public ShareImpl(DeRecSecret.Id secretId, int versionNumber, DeRecHelper.SharerStatus sharerStatus,
                     byte[] committedDeRecShareBytes) {
        this.secretId = secretId;
        this.versionNumber = versionNumber;
        this.sharerStatus = sharerStatus;
        this.committedDeRecShareBytes = committedDeRecShareBytes;
        isConfirmed = false;
    }

    public int getVersionNumber() {
        return versionNumber;
    }

    public DeRecHelper.SharerStatus getSharerStatus() {
        return sharerStatus;
    }

    public byte[] getCommittedDeRecShareBytes() {
        return committedDeRecShareBytes;
    }

    public boolean isConfirmed() {
        return isConfirmed;
    }

    public void updateConfirmation(boolean status) {
        isConfirmed = status;
    }

    @Override
    public DeRecHelper.SharerStatus getSharer() {
        return sharerStatus;
    }

    @Override
    public DeRecSecret.Id getSecretId() {
        return secretId;
    }

    @Override
    public List<Integer> getVersions() {
        ArrayList<Integer> versionsList = new ArrayList<>();
        versionsList.add(versionNumber);
        return versionsList;
    }


    @Override
    public boolean remove() {
        return false;
    }
}
