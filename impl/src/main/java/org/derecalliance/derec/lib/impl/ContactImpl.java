package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecContact;
import org.derecalliance.derec.protobuf.Contact;

import java.net.URI;
import java.util.Arrays;

public class ContactImpl implements DeRecContact {

    private int publicEncryptionKeyId;
    private String publicEncryptionKey;
    private String transportUri;
    private long nonce;


    public ContactImpl(int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri) {
        this.publicEncryptionKeyId = publicEncryptionKeyId;
        this.transportUri = transportUri;
        this.publicEncryptionKey = publicEncryptionKey;
        this.nonce = nonce;
    }
    public ContactImpl() {
    }

    @Override
    public int getPublicEncryptionKeyId() {
        return publicEncryptionKeyId;
    }
    @Override
    public String getTransportUri() {
        return transportUri;
    }

    @Override
    public String getPublicEncryptionKey() {
        return publicEncryptionKey;
    }

    @Override
    public long getNonce() {
        return nonce;
    }

    @Override
    public byte[] createContactMessage(int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri) {
        Contact.ContactMessage contactMessage =
                Contact.ContactMessage.newBuilder()
                        .setPublicKeyId(publicEncryptionKeyId)
                        .setPublicEncryptionKey(publicEncryptionKey)
                        .setNonce(nonce)
                        .setTransportUri(transportUri)
                        .build();
        System.out.println("Created bytes for QR code: " + Arrays.toString(contactMessage.toByteArray()));
        return contactMessage.toByteArray();
    }

    @Override
    public DeRecContact parseContactMessage(byte[] data) {
        System.out.println("Trying to parse bytes for QR code: " + Arrays.toString(data));
        try {
            Contact.ContactMessage contactMessage =
                    Contact.ContactMessage.parseFrom(data);
            var contact = new ContactImpl(contactMessage.getPublicKeyId(), contactMessage.getPublicEncryptionKey(),
                            contactMessage.getNonce(), new URI(contactMessage.getTransportUri()).toString());
            return contact;
        } catch (Exception ex) {
            System.err.println("Invalid protobuf message received in " +
                    "parseContactMessage");
            return null;
        }    }

    public String debugStr() {
        return "Contact key: [id: " + publicEncryptionKeyId + ", Key: " + publicEncryptionKey + ", URI: " + transportUri + ", Nonce: " + nonce + "]\n";
    }
}
