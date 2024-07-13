package org.derecalliance.derec.lib.api;

public interface DeRecContact {
    int getPublicEncryptionKeyId();

    String getTransportUri();

    String getPublicEncryptionKey();

    long getNonce();

    /**
     * Creates the contact message about a user
     *
     * @param publicEncryptionKeyId publicEncryptionKeyId of the user
     * @param publicEncryptionKey   publicEncryptionKey of the user
     * @param nonce                 nonce generated by the user
     * @param transportUri          transportUri of the user
     * @return byte[] Serialized contact
     */
    public byte[] createContactMessage(int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri);

    /**
     * Parses the contact message received from a user
     *
     * @param data Serialized contact
     * @return DeRecContact object
     */
    public DeRecContact parseContactMessage(byte[] data);
}
