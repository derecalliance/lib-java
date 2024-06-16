package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecSharer;
import org.derecalliance.derec.lib.api.SharerFactory;

public class SharerFactoryImpl implements SharerFactory {
    @Override
    public DeRecSharer createSharer(String name, String uri) {
        return new SharerImpl(name, uri);
    }
}
