package org.derecalliance.derec.lib.impl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.Pair;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;

public class ProtobufHttpServer {

    public ProtobufHttpServer(URI uri) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(uri.getPort()),
                10);
        server.createContext("/", new MyHandler());
        server.setExecutor(null);

        Thread serverThread = new Thread(() -> {
            server.start();
            System.out.println("Server started on port -- " + uri.getPort());
        });
        serverThread.start();
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            boolean onlyAcceptPairingMessages = false;
            System.out.println("In http MyHandler::handle");
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream is = exchange.getRequestBody();
                byte[] msgBytes = is.readAllBytes();

//                System.out.print("------ received wire bytes: ");
//                for (int i = 0; i < 20; i++) {
//                    System.out.print(msgBytes[i] + ", ");
//                }
//                System.out.println("");

                exchange.sendResponseHeaders(200, -1);

                int publicKeyId = MessageFactory.extractPublicKeyIdFromPackagedBytes(msgBytes);
                System.out.println("After extractPublicKeyIdFromPackagedBytes(), publicKeyId is: " + publicKeyId);
                byte[] msg = MessageFactory.parsePackagedBytes(msgBytes, true);
                if (msg == null) {
                    onlyAcceptPairingMessages = true;
                    msg = MessageFactory.parsePackagedBytes(msgBytes, false);
                }

//                System.out.print("------ after parsePackagedBytes bytes: ");
//                for (int i = 0; i < 20; i++) {
//                    System.out.print(msg[i] + ", ");
//                }
//                System.out.println("");

                Derecmessage.DeRecMessage derecmessage =
                        Derecmessage.DeRecMessage.parseFrom(msg);

                // If we said that we are only accepting pairing messages, then ensure that either Pairing Request or
                // Pairing Response message is parsable. Otherwise drop the message.
                System.out.println("in handle: onlyAcceptPairingMessages=" + onlyAcceptPairingMessages);
                try {
                    System.out.println("hasPairRequest=" +
                                    (derecmessage.hasMessageBodies() &&
                                            derecmessage.getMessageBodies().hasSharerMessageBodies() &&
                                            derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).hasPairRequestMessage()));

                    System.out.println("hasPairResponse=" + (derecmessage.hasMessageBodies() &&
                            derecmessage.getMessageBodies().hasHelperMessageBodies() &&
                            derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).hasPairResponseMessage()));
                } catch(Exception ex) {
                    System.out.println("Exception in printing hasPairRequest/Response");
                    System.err.println (ex);
                }

                if (!onlyAcceptPairingMessages ||
                        (onlyAcceptPairingMessages &&
                                ((derecmessage.hasMessageBodies() &&
                                        derecmessage.getMessageBodies().hasSharerMessageBodies() &&
                                        derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).hasPairRequestMessage()) ||
                                (derecmessage.hasMessageBodies() &&
                                        derecmessage.getMessageBodies().hasHelperMessageBodies() &&
                                        derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).hasPairResponseMessage()))
                        )) {
                    System.out.println("going to process the message parser");
                    MessageParser mp = new MessageParser();
                    mp.parseMessage(publicKeyId, derecmessage);
                } else {
                    // Drop the message
                    System.out.println("Handle: could not verify the signature on the received message, and it " +
                            "wasn't a pairing message");
                }

//                LibState.getInstance().getIncomingMessageQueue().addRequest(derecmessage);
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }
}
