package org.derecalliance.derec.lib.impl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import org.derecalliance.derec.lib.impl.commands.MessageReceivedCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProtobufHttpServer {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public ProtobufHttpServer(URI uri) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(uri.getPort()), 10);
        server.createContext("/", new MyHandler());
        server.setExecutor(null);

        Thread serverThread = new Thread(() -> {
            server.start();
            logger.debug("Server started on port -- " + uri.getPort());
        });
        serverThread.start();
    }

    static class MyHandler implements HttpHandler {
        Logger logger = LoggerFactory.getLogger(this.getClass().getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            boolean onlyAcceptPairingMessages = false;
            logger.info("In http MyHandler:: Received message");
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream is = exchange.getRequestBody();
                byte[] msgBytes = is.readAllBytes();
                exchange.sendResponseHeaders(200, -1);

                // Enqueue this message to the command queue
                MessageReceivedCommand command = new MessageReceivedCommand(msgBytes);
                LibState.getInstance().getCommandQueue().add(command);
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    public static void processReceivedMesssage(byte[] msgBytes) {
        Logger staticLogger = LoggerFactory.getLogger(ProtobufHttpServer.class.getName());

        try {
            boolean result = MessageFactory.parseAndProcessPackagedBytes(msgBytes);
        } catch (Exception ex) {
            staticLogger.error("Exception in handle", ex);
        }
    }
}
