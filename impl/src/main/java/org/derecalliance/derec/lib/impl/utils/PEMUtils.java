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

import java.util.Base64;

public class PEMUtils {
    public static String encodePublicKeyToPEM(byte[] publicKeyBytes) {
        // Base64 encode the byte array
        String base64EncodedKey = Base64.getEncoder().encodeToString(publicKeyBytes);

        // Format the encoded key into the PEM format
        String pemFormattedKey = "-----BEGIN PUBLIC KEY-----\n";
        pemFormattedKey += insertLineBreaks(base64EncodedKey, 64);
        pemFormattedKey += "\n-----END PUBLIC KEY-----";

        return pemFormattedKey;
    }

    private static String insertLineBreaks(String base64Encoded, int lineLength) {
        StringBuilder stringBuilder = new StringBuilder();
        int index = 0;
        while (index < base64Encoded.length()) {
            stringBuilder.append(base64Encoded, index, Math.min(index + lineLength, base64Encoded.length()));
            stringBuilder.append('\n');
            index += lineLength;
        }
        return stringBuilder.toString();
    }

    public static byte[] decodePEMToByteArray(String pemEncodedString) {
        // Remove the PEM header and footer
        String base64EncodedKey = pemEncodedString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // Base64 decode the content
        return Base64.getDecoder().decode(base64EncodedKey);
    }
}
