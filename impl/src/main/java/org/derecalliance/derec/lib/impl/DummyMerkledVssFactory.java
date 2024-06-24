package org.derecalliance.derec.lib.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class DummyMerkledVssFactory {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public List<byte[]> split(byte[] secretId, int versionNumber, byte[] bytesToProtect, int count, int threshold) {
        if (LibState.getInstance().useRealCryptoLib) {
              return LibState.getInstance().getDerecCryptoImpl().share(secretId, versionNumber, bytesToProtect, count,
                    threshold);
        } else {
            ArrayList<byte[]> ret = new ArrayList<byte[]>();
            for (int i = 0; i < count; i++) {
                ret.add(bytesToProtect);
            }
            return ret;
        }
    }

    public byte[] combine(byte[] secretId, int versionNumber, List<byte[]> shares) {
        logger.debug("In combine. List size is: " + shares.size());

        if (shares.size() < LibState.getInstance().getMinNumberOfHelpersForRecovery()) {
            return null;
        }
        try {
            if (LibState.getInstance().useRealCryptoLib) {
                 return LibState.getInstance().getDerecCryptoImpl().recover(secretId, versionNumber, shares);
                // TODO: if the recover is unsuccessful, recover() may return null -- this needs to be handled
            } else {
                return shares.get(0);
            }
        } catch (Exception ex) {
            logger.error("Exception in combine");
            ex.printStackTrace();
            return null;
        }
    }
}
