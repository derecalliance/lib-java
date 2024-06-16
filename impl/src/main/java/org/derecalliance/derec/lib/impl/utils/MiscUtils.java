package org.derecalliance.derec.lib.impl.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class MiscUtils {

    public static byte[] intToByteArray(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
    public static int readInt(ByteArrayInputStream bais) {
        byte[] intBytes = new byte[4];
        bais.read(intBytes, 0, 4);
        return ByteBuffer.wrap(intBytes).getInt();
    }

    public static byte[] readByteArray(ByteArrayInputStream bais) {
        int length = readInt(bais);
        byte[] array = new byte[length];
        bais.read(array, 0, length);
        return array;
    }

    public static void writeToByteArrayOutputStream(ByteArrayOutputStream baos, byte[] bytes) throws IOException {
        baos.write(intToByteArray(bytes.length));
        baos.write(bytes);
    }

    public static int readIntFromByteArrayInputStream(ByteArrayInputStream bais) {
        byte[] intBytes = new byte[4];
        bais.read(intBytes, 0, 4);
        return ByteBuffer.wrap(intBytes).getInt();
    }

    public static byte[] readByteArrayFromByteArrayInputStream(ByteArrayInputStream bais) {
        byte[] lengthBytes = new byte[4];
        bais.read(lengthBytes, 0, 4);
        int length = ByteBuffer.wrap(lengthBytes).getInt();
        byte[] data = new byte[length];
        bais.read(data, 0, length);
        return data;
    }
}
