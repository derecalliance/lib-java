package org.derecalliance.derec.lib.impl;

import com.google.protobuf.Timestamp;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.Pair;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;


public class ProtobufHttpClient {

    public static void main(String[] args) throws IOException, InterruptedException {
        Pair.PairRequestMessage pairRequestMessage =
            Pair.PairRequestMessage
                    .newBuilder()
                    .setPublicEncryptionKey("TestPUBLICKey")
                    .setNonce(12345L)
                    .build();

        Derecmessage.DeRecMessage deRecMessage = Derecmessage.DeRecMessage.newBuilder()
                .setProtocolVersionMajor(0) // Set the protocol version major
                .setProtocolVersionMinor(9) // Set the protocol version minor
//                .setSender(/* byte array for sender's SHA-384 hash */)
//                .setReceiver(/* byte array for receiver's SHA-384 hash */)
//                .setSecretId(/* byte array for secret ID */)
                .setTimestamp(Timestamp.newBuilder()
                        .setSeconds(Instant.now().getEpochSecond())
                        .setNanos(Instant.now().getNano())
                        .build())
                .setMessageBodies(Derecmessage.DeRecMessage.MessageBodies.newBuilder()
                        .setSharerMessageBodies(Derecmessage.DeRecMessage.SharerMessageBodies.newBuilder()
                                .addSharerMessageBody(Derecmessage.DeRecMessage.SharerMessageBody.newBuilder()
                                        .setPairRequestMessage(pairRequestMessage)
                                        .build())
                                .build())
                        .build())
                .build();

//        SimpleMessage message = SimpleMessage.newBuilder()
//                .setContent("Hello, Server!")
//                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8001/message"))
                .header("Content-Type", "application/x-protobuf")
                .POST(BodyPublishers.ofByteArray(deRecMessage.toByteArray()))
                .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());

        if (response.statusCode() == 200) {
            Pair.PairResponseMessage responseMessage =
                    Pair.PairResponseMessage.parseFrom(response.body());
            System.out.println("Received: Pair response with nonce: " +
                    responseMessage.getNonce() + ",  pub sign key: " + responseMessage.getPublicSignatureKey());
        } else {
            System.out.println("Response status code: " + response.statusCode());
        }
    }

    public static int sendHttpRequest(String toUri, byte[] msgBytes) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(toUri))
                .header("Content-Type", "application/x-protobuf")
                .POST(BodyPublishers.ofByteArray(msgBytes))
                .build();

//        HttpClient client = HttpClient.newHttpClient();
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(1))
                .build();
        HttpResponse<InputStream> response = null;
        try {
            System.out.println("About to call client.send");
            response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            System.out.println("After the call to client.send");

        } catch (HttpConnectTimeoutException ex) {
            System.out.println("Could not send http message to " + toUri);
            return (400);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (response.statusCode() == 200) {
            System.out.println("Received good http response");
        } else {
            System.out.println("Response status code: " + response.statusCode());
        }
        return response.statusCode();
    }
}
