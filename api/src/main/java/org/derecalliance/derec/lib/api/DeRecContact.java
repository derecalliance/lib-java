package org.derecalliance.derec.lib.api;

public interface DeRecContact {
    int getPublicEncryptionKeyId();
    String getTransportUri();
    String getPublicEncryptionKey();
    long getNonce();

    public byte[] createContactMessage(int publicEncryptionKeyId, String publicEncryptionKey, long nonce, String transportUri);
    public DeRecContact parseContactMessage(byte[] data);
}
