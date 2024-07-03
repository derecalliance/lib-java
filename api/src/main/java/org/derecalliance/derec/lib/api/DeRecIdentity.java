/*
 * Copyright (c) 2023 The Building Blocks Limited.
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

package org.derecalliance.derec.lib.api;

//import com.google.protobuf.ByteString;
//import org.derecalliance.derec.lib.LibState;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

//import static org.derecalliance.derec.lib.utils.MiscUtils.*;

/**
 * Information about the identity of a helper or a sharer
 */
public class DeRecIdentity {
    private static final MessageDigest messageDigest;

    static {
        try {
            messageDigest = MessageDigest.getInstance("SHA-384");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private final String name; // human-readable identification
    private final String contact; // how to contact me outside the protocol, an
    // email address, for example
    private final String address; // transport address
    private int publicEncryptionKeyId;
    private final String publicEncryptionKey;
    private String publicSignatureKey;
    private final byte[] publicEncryptionKeyDigest;
    private byte[] publicSignatureKeyDigest;


    /**
     * Create a helper info
     * @param name human-readable name
     * @param contact contact address - e.g. email
     * @param address DeRec address
     * @param publicEncryptionKeyId public encryption key id
     * @param publicEncryptionKey PEM encoded public encryption key
     * @param publicSignatureKey PEM encoded public signature key
     */
    public DeRecIdentity(String name, String contact, String address, int publicEncryptionKeyId, String publicEncryptionKey, String publicSignatureKey) {
        this.name = name;
        this.contact = contact;
        this.address = Objects.isNull(address) ? null : address;
        this.publicEncryptionKeyId = publicEncryptionKeyId;
        this.publicEncryptionKey = publicEncryptionKey;
        this.publicSignatureKey = publicSignatureKey;
        this.publicEncryptionKeyDigest = messageDigest.digest(Base64.getDecoder().decode(publicEncryptionKey));
        if (publicSignatureKey != null) {
            this.publicSignatureKeyDigest = messageDigest.digest(Base64.getDecoder().decode(publicSignatureKey));
        }
//        LibState.getInstance().messageHashToIdentityMap.put(ByteString.copyFrom(this.publicKeyDigest), this);
    }

    /**
     * @return human-readable name
     */
    public String getName() {
        return name;
    }

    /**
     * @return human readable contact info, e.g. email address
     */
    public String getContact() {
        return contact;
    }

    /**
     * @return network address for DeRec protocol
     */
    public String getAddress() {
        return address;
    }

    /**
     * @return public encryption key id
     */
    public int getPublicEncryptionKeyId() {
        return publicEncryptionKeyId;
    }

    /**
     * @return PEM encoded public encryption key
     */
    public String getPublicEncryptionKey() {
        return publicEncryptionKey;
    }

    /**
     * @return PEM encoded public signature key
     */
    public String getPublicSignatureKey() {
        return publicSignatureKey;
    }

    public byte[] getPublicEncryptionKeyDigest() {
        return publicEncryptionKeyDigest;
    }

    public byte[] getPublicSignatureKeyDigest() {
        return publicSignatureKeyDigest;
    }

    public void setPublicSignatureKey(String publicSignatureKey) {
        System.out.println("In setPublicSignatureKey: " + publicSignatureKey);
        this.publicSignatureKey = publicSignatureKey;
        this.publicSignatureKeyDigest = messageDigest.digest(Base64.getDecoder().decode(publicSignatureKey));
    }

    /**
     * Used to set the publicEncryptionKeyId of the helper after receiving their Contact
     * @param publicEncryptionKeyId public encryption key id
     */
    public void setPublicEncryptionKeyId(int publicEncryptionKeyId) {
        this.publicEncryptionKeyId = publicEncryptionKeyId;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeRecIdentity deRecId)) return false;
        return Objects.equals(getName(), deRecId.getName()) &&
                Objects.equals(getContact(), deRecId.getContact()) &&
                Objects.equals(getAddress(), deRecId.getAddress()) &&
                Objects.equals(getPublicEncryptionKey(), deRecId.getPublicEncryptionKey()) &&
                Objects.equals(getPublicSignatureKey(), deRecId.getPublicSignatureKey());
    }

    public boolean equalsKey(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeRecIdentity deRecId)) return false;
        return Objects.equals(getPublicEncryptionKey(), deRecId.getPublicEncryptionKey()) &&
                Objects.equals(getPublicSignatureKey(), deRecId.getPublicSignatureKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getContact(), getAddress(), getPublicEncryptionKey(), getPublicSignatureKey());
    }


    public String toString() {
        return "Name: " + name + ", Contact: " + contact + ", Address: " + address +
                ", pubEncryptionKeyId: " + (publicEncryptionKeyId == 0 ? "null" : publicEncryptionKeyId) +
                ", pubEncryptionKeyDigest: " + (publicEncryptionKeyDigest == null ? "null" : Base64.getEncoder().encodeToString(publicEncryptionKeyDigest)) +
                ", pubSignatureKeyDigest: " + (publicSignatureKeyDigest == null ? "null" : Base64.getEncoder().encodeToString(publicSignatureKeyDigest));
    }
}
