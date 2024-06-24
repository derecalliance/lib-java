package org.derecalliance.derec.lib.impl;

import com.google.protobuf.ByteString;
import org.derecalliance.derec.lib.api.DeRecSecret;
import org.derecalliance.derec.protobuf.Storeshare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class CommittedDeRecShare {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public static class DeRecShare {
        byte[] encryptedSecret;
        byte[] x;
        byte[] y;
        DeRecSecret.Id secretId;
        int version;
        String versionDescription;
        DeRecShare(Storeshare.DeRecShare message) {
            encryptedSecret = message.getEncryptedSecret().toByteArray();
            x = message.getX().toByteArray();
            y = message.getY().toByteArray();
            secretId = new SecretImpl.Id(message.getSecretId().toByteArray());
            version = message.getVersion();
            versionDescription = message.getVersionDescription();
        }

        public DeRecShare(byte[] encryptedSecret, byte[] x, byte[] y, DeRecSecret.Id secretId, int version,
                          String versionDescription) {
            this.encryptedSecret = encryptedSecret;
            this.x = x;
            this.y = y;
            this.secretId = secretId;
            this.version = version;
            this.versionDescription = versionDescription;
        }

        public Storeshare.DeRecShare createDeRecShareMessage() {
            Storeshare.DeRecShare deRecShareMessage =
                    Storeshare.DeRecShare.newBuilder()
                            .setEncryptedSecret(ByteString.copyFrom(encryptedSecret))
                            .setX(ByteString.copyFrom(x))
                            .setY(ByteString.copyFrom(y))
                            .setSecretId(ByteString.copyFrom(secretId.getBytes()))
                            .setVersion(version)
                            .setVersionDescription(versionDescription)
                            .build();
            return deRecShareMessage;
        }

        public byte[] getEncryptedSecret() {
            return encryptedSecret;
        }

        public byte[] getX() {
            return x;
        }

        public byte[] getY() {
            return y;
        }

        public DeRecSecret.Id getSecretId() {
            return secretId;
        }

        public int getVersion() {
            return version;
        }

        public String getVersionDescription() {
            return versionDescription;
        }

        public String toString() {
            String str = "";
            str += "Encrypted secret: " + Base64.getEncoder().encodeToString(encryptedSecret) + "\n";
            str += "x: " + Base64.getEncoder().encodeToString(x) + "\n";
            str += "y: " + Base64.getEncoder().encodeToString(y) + "\n";
            str += "Secret id: " + Base64.getEncoder().encodeToString(secretId.getBytes()) + "\n";
            str += "VersionImpl: " + version + ", Description: " + versionDescription + "\n";
            return str;
        }
    }

    public class SiblingHash {
        boolean isLeft;
        byte[] hash;

        public SiblingHash(boolean isLeft, byte[] hash) {
            this.isLeft = isLeft;
            this.hash = hash;
        }

        public boolean isLeft() {
            return isLeft;
        }

        public byte[] getHash() {
            return hash;
        }
        public String toString() {
            String str = "";
            str += "isLeft: " + (isLeft ? "Left" : "Right") + ", ";
            str += "Hash: " + Base64.getEncoder().encodeToString(hash) + "\n";
            return str;
        }
    }
    DeRecShare deRecShare;
    byte[] commitment;
    ArrayList<SiblingHash> siblingHashes;

    public CommittedDeRecShare(Storeshare.CommittedDeRecShare message) {
        try {
            deRecShare = new DeRecShare(Storeshare.DeRecShare.parseFrom(message.getDeRecShare()));
            siblingHashes = new ArrayList<>();
            commitment = message.getCommitment().toByteArray();
            List<Storeshare.CommittedDeRecShare.SiblingHash> merklePathList = message.getMerklePathList();
            for (Storeshare.CommittedDeRecShare.SiblingHash entry : merklePathList) {
                siblingHashes.add(new SiblingHash(entry.getIsLeft(), entry.getHash().toByteArray()));
            }
        } catch (Exception ex) {
            logger.error("Exception in CommittedDeRecShare constructor");
            ex.printStackTrace();
            return;
        }
    }

    public CommittedDeRecShare(DeRecShare deRecShare, byte[] commitment, ArrayList<SiblingHash> siblingHashes) {
        this.deRecShare = deRecShare;
        this.commitment = commitment;
        this.siblingHashes = siblingHashes;
    }

    public DeRecShare getDeRecShare() {
        return deRecShare;
    }

    public byte[] getCommitment() {
        return commitment;
    }

    public ArrayList<SiblingHash> getSiblingHashes() {
        return siblingHashes;
    }

    // Utility functions to deal with committed derec share
    public Storeshare.CommittedDeRecShare createCommittedDeRecShareMessage() {
        Storeshare.CommittedDeRecShare.Builder committedDeRecShareBuilder =
                Storeshare.CommittedDeRecShare.newBuilder()
                        .setDeRecShare(deRecShare.createDeRecShareMessage().toByteString())
                        .setCommitment(ByteString.copyFrom(commitment));
        for (SiblingHash siblingHash : siblingHashes) {
            Storeshare.CommittedDeRecShare.SiblingHash siblingHashMessage =
                    Storeshare.CommittedDeRecShare.SiblingHash.newBuilder()
                            .setIsLeft(siblingHash.isLeft)
                            .setHash(ByteString.copyFrom(siblingHash.getHash()))
                            .build();
            committedDeRecShareBuilder.addMerklePath(siblingHashMessage);
        }
        Storeshare.CommittedDeRecShare committedDeRecShareMessage = committedDeRecShareBuilder.build();
        return committedDeRecShareMessage;
    }

    public String toString() {
        String str = "";
        str += deRecShare.toString();
        str += "commitment: " + Base64.getEncoder().encodeToString(commitment) + "\n";
        str += siblingHashes.stream()
                .map(SiblingHash::toString)
                .collect(Collectors.joining(", "));
        str += "\n";
        return str;
    }
}
