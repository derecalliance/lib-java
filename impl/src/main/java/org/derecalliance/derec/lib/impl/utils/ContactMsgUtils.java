package org.derecalliance.derec.lib.impl.utils;

import org.derecalliance.derec.lib.impl.ContactImpl;
import org.derecalliance.derec.protobuf.Contact;

import java.net.URI;
import java.util.Arrays;

public class ContactMsgUtils {

    public static byte[] createContactMessage(int publicEncryptionKeyId,
                                              String publicEncryptionKey,
                                          long nonce,
                         String transportUri) {
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
    public static ContactImpl parseContactMessage(byte[] data)  {
        System.out.println("Trying to parse bytes for QR code: " + Arrays.toString(data));

        try {
//            Base64.getDecoder().decode(base64String);
            Contact.ContactMessage contactMessage =
                    Contact.ContactMessage.parseFrom(data);
            var contact = new ContactImpl(contactMessage.getPublicKeyId(), contactMessage.getPublicEncryptionKey(),
                    contactMessage.getNonce(), new URI(contactMessage.getTransportUri()).toString());
            return contact;
        } catch (Exception ex) {
            System.err.println("Invalid protobuf message received in " +
                    "parseContactMessage");
            return null;
        }
    }
}
