package org.derecalliance.derec.lib.impl;

import static org.derecalliance.derec.lib.impl.utils.MiscUtils.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.derecalliance.derec.lib.api.DeRecIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdentityImpl extends DeRecIdentity {

    /**
     * Create a helper info
     *
     * @param name                  human-readable name
     * @param contact               contact address - e.g. email
     * @param address               DeRec address
     * @param publicEncryptionKeyId public encryption key id
     * @param publicEncryptionKey   PEM encoded public encryption key
     * @param publicSignatureKey    PEM encoded public signature key
     */
    public IdentityImpl(
            String name,
            String contact,
            String address,
            int publicEncryptionKeyId,
            String publicEncryptionKey,
            String publicSignatureKey) {
        super(name, contact, address, publicEncryptionKeyId, publicEncryptionKey, publicSignatureKey);
    }

    public static byte[] serializeDeRecIdentity(DeRecIdentity identity) throws IOException {
        Logger staticLogger = LoggerFactory.getLogger(IdentityImpl.class.getName());

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writeToByteArrayOutputStream(baos, identity.getName().getBytes());
            writeToByteArrayOutputStream(baos, identity.getContact().getBytes());
            writeToByteArrayOutputStream(baos, identity.getAddress().getBytes());
            baos.write(intToByteArray(identity.getPublicEncryptionKeyId()));
            writeToByteArrayOutputStream(baos, identity.getPublicEncryptionKey().getBytes());
            writeToByteArrayOutputStream(baos, identity.getPublicSignatureKey().getBytes());
            return baos.toByteArray();
        } catch (Exception ex) {
            staticLogger.error("Exception in serializeDeRecIdentity", ex);
            return new byte[0];
        }
    }

    public static DeRecIdentity deserializeDeRecIdentity(byte[] data) throws IOException, ClassNotFoundException {
        Logger staticLogger = LoggerFactory.getLogger(IdentityImpl.class.getName());

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            String name = new String(readByteArrayFromByteArrayInputStream(bais));
            String contact = new String(readByteArrayFromByteArrayInputStream(bais));
            String address = new String(readByteArrayFromByteArrayInputStream(bais));
            int publicEncryptionKeyId = readIntFromByteArrayInputStream(bais);
            String publicEncryptionKey = new String(readByteArrayFromByteArrayInputStream(bais));
            String publicSignatureKey = new String(readByteArrayFromByteArrayInputStream(bais));
            return new DeRecIdentity(
                    name, contact, address, publicEncryptionKeyId, publicEncryptionKey, publicSignatureKey);
        } catch (Exception ex) {
            staticLogger.error("Exception in deserializeDeRecIdentity", ex);
            return null;
        }
    }
}
