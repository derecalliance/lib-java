/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
