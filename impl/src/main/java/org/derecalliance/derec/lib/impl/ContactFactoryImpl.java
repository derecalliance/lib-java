package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecContact;
import org.derecalliance.derec.lib.api.ContactFactory;

public class ContactFactoryImpl implements ContactFactory {
    @Override
    public DeRecContact createContact(int publicEncryptionKeyId, String publicEncryptionKey, long nonce,
                                      String transportUri) {
        return new ContactImpl(publicEncryptionKeyId,  publicEncryptionKey,  nonce, transportUri);
    }

    @Override
    public DeRecContact createContact() {
        return new ContactImpl();
    }
}
