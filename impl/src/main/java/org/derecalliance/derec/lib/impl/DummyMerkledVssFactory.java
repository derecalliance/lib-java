package org.derecalliance.derec.lib.impl;

import java.util.ArrayList;
import java.util.List;

public class DummyMerkledVssFactory {

    public List<byte[]> split(byte[] secretId, int versionNumber, byte[] bytesToProtect, int count, int threshold) {
        // public List<byte[]> share(byte[] id, int version, byte[] secret, int count, int threshold);
        final boolean useRealCryptoLib = false;
        if (useRealCryptoLib) {
             // return share(secretId, versionNumber, bytesToProtect, count, threshold); //TODO: uncomment this (useCryptoLib)
            return new ArrayList<>();
        } else {
            ArrayList<byte[]> ret = new ArrayList<byte[]>();
            for (int i = 0; i < count; i++) {
                ret.add(bytesToProtect);
            }
            return ret;
        }
    }

    public byte[] combine(byte[] secretId, int versionNumber, List<byte[]> shares) {
        System.out.println("In combine. List size is: " + shares.size());

        if (shares.size() < LibState.getInstance().getMinNumberOfHelpersForRecovery()) {
            return null;
        }
        try {
            final boolean useRealCryptoLib = false;
            if (useRealCryptoLib) {
                // return recover(secretId, versionNumber, shares) //TODO: uncomment this (useCryptoLib)
                // TODO: if the recover is unsuccessful, recover() may return null -- this needs to be handled
                return ("hello").getBytes();
            } else {
                return shares.get(0);
            }
        } catch (Exception ex) {
            System.out.println("Exception in combine");
            ex.printStackTrace();
            return null;
        }
    }
}
