package org.derecalliance.derec.lib.api;

public interface ContactFactory {
    public DeRecContact createContact(int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri);
    public DeRecContact createContact();

}

