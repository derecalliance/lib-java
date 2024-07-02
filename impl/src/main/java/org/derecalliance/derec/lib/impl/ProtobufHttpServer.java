package org.derecalliance.derec.lib.impl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.derecalliance.derec.protobuf.Derecmessage;
import org.derecalliance.derec.protobuf.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;

public class ProtobufHttpServer {
    Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public ProtobufHttpServer(URI uri) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(uri.getPort()),
                10);
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

//                System.out.print("------ received wire bytes: ");
//                for (int i = 0; i < 20; i++) {
//                    System.out.print(msgBytes[i] + ", ");
//                }
//                staticLogger.debug("");

                exchange.sendResponseHeaders(200, -1);

                try {
                    boolean result = MessageFactory.parseAndProcessPackagedBytes(msgBytes);
                } catch (Exception ex) {
                    logger.debug("Exception in handle", ex);
                }

                boolean old_code = false;
                if (old_code) {
//                    int publicKeyId = MessageFactory.extractPublicKeyIdFromPackagedBytes(msgBytes);
//                    logger.info("After extractPublicKeyIdFromPackagedBytes(), publicKeyId is: " + publicKeyId);
//                    byte[] msg = null;
//                    try {
//                        msg = MessageFactory.parsePackagedBytes(msgBytes, true);
//                    } catch (Exception ex) {
//                        logger.error("Exception in MessageFactory.parsePackagedBytes  with verificationNeeded = true. " +
//                                "msgBytes: " + msgBytes, ex);
//                    }
//                    logger.debug("After parsePackagedBytes with verificationNeeded=true, msg = " + msg);
//                    if (msg == null) {
//                        onlyAcceptPairingMessages = true;
//                        try {
//                            msg = MessageFactory.parsePackagedBytes(msgBytes, false);
//                        } catch (Exception ex) {
//                            logger.error("Exception in MessageFactory.parsePackagedBytes with verificationNeeded = false." +
//                                    " msgBytes: " + msgBytes, ex);
//                        }
//                        logger.debug("After parsePackagedBytes with verificationNeeded=false, msg = " + msg);
//                    }
//
////                System.out.print("------ after parsePackagedBytes bytes: ");
////                for (int i = 0; i < 20; i++) {
////                    System.out.print(msg[i] + ", ");
////                }
////                staticLogger.debug("");
//
//                    Derecmessage.DeRecMessage derecmessage =
//                            Derecmessage.DeRecMessage.parseFrom(msg);
//
//                    // If we said that we are only accepting pairing messages, then ensure that either Pairing Request or
//                    // Pairing Response message is parsable. Otherwise drop the message.
//                    logger.debug("in handle: onlyAcceptPairingMessages=" + onlyAcceptPairingMessages);
//
////                try {
////                    logger.debug("hasPairRequest=" +
////                                    (derecmessage.hasMessageBodies() &&
////                                            derecmessage.getMessageBodies().hasSharerMessageBodies() &&
////                                            derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).hasPairRequestMessage()));
////
////                    logger.debug("hasPairResponse=" + (derecmessage.hasMessageBodies() &&
////                            derecmessage.getMessageBodies().hasHelperMessageBodies() &&
////                            derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).hasPairResponseMessage()));
////                } catch(Exception ex) {
////                    logger.error("Exception in printing hasPairRequest/Response");
////                    System.err.println (ex);
////                }
//
//                    if (!onlyAcceptPairingMessages ||
//                            (onlyAcceptPairingMessages &&
//                                    ((derecmessage.hasMessageBodies() &&
//                                            derecmessage.getMessageBodies().hasSharerMessageBodies() &&
//                                            derecmessage.getMessageBodies().getSharerMessageBodies().getSharerMessageBody(0).hasPairRequestMessage()) ||
//                                            (derecmessage.hasMessageBodies() &&
//                                                    derecmessage.getMessageBodies().hasHelperMessageBodies() &&
//                                                    derecmessage.getMessageBodies().getHelperMessageBodies().getHelperMessageBody(0).hasPairResponseMessage()))
//                            )) {
////                    logger.debug("going to process the message parser");
//                        MessageParser mp = new MessageParser();
//                        mp.parseMessage(publicKeyId, derecmessage);
//                    } else {
//                        // Drop the message
//                        logger.info("Handle: could not verify the signature on the received message, and it " +
//                                "wasn't a pairing message. Dropping");
//                    }
//
////                LibState.getInstance().getIncomingMessageQueue().addRequest(derecmessage);
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }
}
