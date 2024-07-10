package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Storeshare;

import java.util.ArrayList;
import java.util.List;

public class ShareImpl implements DeRecHelper.Share {
    private int versionNumber;
    private DeRecHelper.SharerStatus sharerStatus;
    private DeRecSecret.Id secretId;
    private Storeshare.CommittedDeRecShare committedDeRecShare;
    private boolean isConfirmed;

    public ShareImpl(DeRecSecret.Id secretId, int versionNumber, DeRecHelper.SharerStatus sharerStatus,
                     Storeshare.CommittedDeRecShare committedDeRecShare) {
        this.secretId = secretId;
        this.versionNumber = versionNumber;
        this.sharerStatus = sharerStatus;
        this.committedDeRecShare = committedDeRecShare;
        isConfirmed = false;
    }

    /**
     * Get the version number of this share.
     *
     * @return version number
     */
    public int getVersionNumber() {
        return versionNumber;
    }

    /**
     * Get the SharerStatus associated with this share.
     *
     * @return SharerStatus object
     */
    public DeRecHelper.SharerStatus getSharerStatus() {
        return sharerStatus;
    }

    /**
     * Get protobuf message CommittedDeRecShare
     *
     * @return CommittedDeRecShare
     */
    public Storeshare.CommittedDeRecShare getCommittedDeRecShare() {
        return committedDeRecShare;
    }

    /**
     * Whether the share is confirmed (i.e. it has been verified by the Helper)
     *
     * @return boolean whether share is confirmed
     */
    public boolean isConfirmed() {
        return isConfirmed;
    }

    /**
     * Update whether this share has been confirmed
     *
     * @param status boolean value for whether share has been confirmed
     */
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
