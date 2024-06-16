package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecIdentity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.derecalliance.derec.lib.impl.utils.MiscUtils.readByteArrayFromByteArrayInputStream;
import static org.derecalliance.derec.lib.impl.utils.MiscUtils.writeToByteArrayOutputStream;

public class IdentityImpl extends DeRecIdentity {

    /**
     * Create a helper info
     *
     * @param name      human-readable name
     * @param contact   contact address - e.g. email
     * @param address   DeRec address
     * @param publicEncryptionKey PEM encoded public encryption key
     * @param publicSignatureKey PEM encoded public signature key
     */
    public IdentityImpl(String name, String contact, String address, String publicEncryptionKey,
                        String publicSignatureKey) {
        super(name, contact, address, publicEncryptionKey, publicSignatureKey);
    }

    public static byte[] serializeDeRecIdentity(DeRecIdentity identity) throws IOException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writeToByteArrayOutputStream(baos, identity.getName().getBytes());
            writeToByteArrayOutputStream(baos, identity.getContact().getBytes());
            writeToByteArrayOutputStream(baos, identity.getAddress().getBytes());
            writeToByteArrayOutputStream(baos, identity.getPublicEncryptionKey().getBytes());
            writeToByteArrayOutputStream(baos, identity.getPublicSignatureKey().getBytes());
            return baos.toByteArray();
        } catch (Exception ex) {
            System.out.printf("Exception in serializeDeRecIdentity");
            ex.printStackTrace();
            return null;
        }
    }
    public static DeRecIdentity deserializeDeRecIdentity(byte[] data) throws IOException, ClassNotFoundException {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            String name = new String(readByteArrayFromByteArrayInputStream(bais));
            String contact = new String(readByteArrayFromByteArrayInputStream(bais));
            String address = new String(readByteArrayFromByteArrayInputStream(bais));
            String publicEncryptionKey = new String(readByteArrayFromByteArrayInputStream(bais));
            String publicSignatureKey = new String(readByteArrayFromByteArrayInputStream(bais));
            return new DeRecIdentity(name, contact, address, publicEncryptionKey, publicSignatureKey);
        } catch (Exception ex) {
            System.out.printf("Exception in deserializeDeRecIdentity");
            ex.printStackTrace();
            return null;
        }
    }
}
