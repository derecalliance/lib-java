package org.derecalliance.derec.lib.impl;

import org.derecalliance.derec.lib.api.DeRecHelper;
import org.derecalliance.derec.lib.api.HelperFactory;

public class HelperFactoryImpl implements HelperFactory {
    @Override
    public DeRecHelper createHelper(String name, String contact, String address) {
        return new HelperImpl(name, contact, address);
    }
}
