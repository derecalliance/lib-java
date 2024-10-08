/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.derecalliance.derec.lib.impl;

import java.net.URI;
import java.util.Arrays;
import org.derecalliance.derec.lib.api.DeRecContact;
import org.derecalliance.derec.protobuf.Contact;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ContactImpl implements DeRecContact {
    private int publicEncryptionKeyId;
    private String publicEncryptionKey;
    private String transportUri;
    private long nonce;
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public ContactImpl(int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri) {
        this.publicEncryptionKeyId = publicEncryptionKeyId;
        this.transportUri = transportUri;
        this.publicEncryptionKey = publicEncryptionKey;
        this.nonce = nonce;
    }

    public ContactImpl() {}

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
    public byte[] createContactMessage(
            int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri) {
        Contact.ContactMessage contactMessage = Contact.ContactMessage.newBuilder()
                .setPublicKeyId(publicEncryptionKeyId)
                .setPublicEncryptionKey(publicEncryptionKey)
                .setNonce(nonce)
                .setTransportUri(transportUri)
                .build();
        logger.debug("Created bytes for QR code: " + Arrays.toString(contactMessage.toByteArray()));
        return contactMessage.toByteArray();
    }

    @Override
    public DeRecContact parseContactMessage(byte[] data) {
        logger.debug("Trying to parse bytes for QR code: " + Arrays.toString(data));
        try {
            Contact.ContactMessage contactMessage = Contact.ContactMessage.parseFrom(data);
            var contact = new ContactImpl(
                    contactMessage.getPublicKeyId(),
                    contactMessage.getPublicEncryptionKey(),
                    contactMessage.getNonce(),
                    new URI(contactMessage.getTransportUri()).toString());
            return contact;
        } catch (Exception ex) {
            System.err.println("Invalid protobuf message received in " + "parseContactMessage");
            return null;
        }
    }

    public String debugStr() {
        return "Contact key: [id: " + publicEncryptionKeyId + ", Key: " + publicEncryptionKey + ", URI: " + transportUri
                + ", Nonce: " + nonce + "]\n";
    }
}
