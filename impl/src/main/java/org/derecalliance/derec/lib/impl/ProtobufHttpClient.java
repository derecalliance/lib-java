package org.derecalliance.derec.lib.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides HTTP client interface to send HTTP messages
 */
public class ProtobufHttpClient {
    public static int sendHttpRequest(String toUri, byte[] msgBytes) {
        Logger staticLogger = LoggerFactory.getLogger(ProtobufHttpClient.class.getName());
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(toUri))
                .header("Content-Type", "application/x-protobuf")
                .POST(BodyPublishers.ofByteArray(msgBytes))
                .build();

        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(1))
                .build();
        HttpResponse<InputStream> response = null;
        try {
            staticLogger.debug("About to call client.send");
            response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            staticLogger.debug("After the call to client.send");

        } catch (HttpConnectTimeoutException ex) {
            staticLogger.debug("Could not send http message to " + toUri);
            return (400);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (response.statusCode() == 200) {
            staticLogger.debug("Received good http response");
        } else {
            staticLogger.debug("Response status code: " + response.statusCode());
        }
        return response.statusCode();
    }
}
