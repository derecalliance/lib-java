module org.derecalliance.derec.lib.impl {
    requires org.derecalliance.derec.lib.api;
    requires protobuf.java;
    requires jdk.httpserver;
    requires java.net.http;
    requires org.slf4j;
    requires derec.crypto.bridge;
    exports org.derecalliance.derec.lib.impl;
    exports org.derecalliance.derec.lib.impl.commands;

    provides org.derecalliance.derec.lib.api.SharerFactory with
            org.derecalliance.derec.lib.impl.SharerFactoryImpl;
    provides org.derecalliance.derec.lib.api.HelperFactory with
            org.derecalliance.derec.lib.impl.HelperFactoryImpl;
    provides org.derecalliance.derec.lib.api.ContactFactory with
            org.derecalliance.derec.lib.impl.ContactFactoryImpl;
}
