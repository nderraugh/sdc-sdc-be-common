/*-
 * ============LICENSE_START=======================================================
 * SDC
 * ================================================================================
 * Copyright (C) 2017 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ============LICENSE_END=========================================================
 */

package org.onap.sdc.security;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import org.onap.sdc.security.logging.wrappers.Logger;

public class SecurityUtil {

    private static final Logger LOG = Logger.getLogger(SecurityUtil.class);
    public static final SecurityUtil INSTANCE = new SecurityUtil();
    public static final String ALGORITHM = "AES";
    public static final String CHARSET = UTF_8.name();

    private static final Key secKey2 = generateKey(ALGORITHM);

    /**
     * cmd commands >$PROGRAM_NAME decrypt "$ENCRYPTED_MSG" >$PROGRAM_NAME encrypt "message"
     */
    private SecurityUtil() {
    }

    // obfuscates key prefix -> **********
    public String obfuscateKey(String sensitiveData) {

        if (sensitiveData == null) {
            return null;
        }
        int len = sensitiveData.length();
        StringBuilder builder = new StringBuilder(sensitiveData);
        for (int i = 0; i < len / 2; i++) {
            builder.setCharAt(i, '*');
        }
        return builder.toString();
    }

    public static final int GCM_TAG_LENGTH = 16;
    public static final int GCM_IV_LENGTH = 12;

    public static SecretKey generateKey(String algorithm) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(algorithm);
            kgen.init(128);
            return kgen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.toString());
        }
    }

    public static String encrypt_gcm(String plaintext) {
        /* Precond: skey is valid and GCM mode is available in the JRE;
         * otherwise IllegalStateException will be thrown. */
        try {
            byte[] ciphertext = null;
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] initVector = new byte[GCM_IV_LENGTH];
            (new SecureRandom()).nextBytes(initVector);
            GCMParameterSpec spec =
                new GCMParameterSpec(GCM_TAG_LENGTH * java.lang.Byte.SIZE, initVector);
            cipher.init(Cipher.ENCRYPT_MODE, secKey2, spec);
            byte[] encoded = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            //ciphertext = new byte[initVector.length + cipher.getOutputSize(encoded.length)];
            ciphertext = Arrays
                .copyOf(initVector, initVector.length + cipher.getOutputSize(encoded.length));
//            for (int i = 0; i < initVector.length; i++) {
//                ciphertext[i] = initVector[i];
//            }
            // Perform encryption
            cipher.doFinal(encoded, 0, encoded.length, ciphertext, initVector.length);
            String strCipherText = new String(Base64.getMimeEncoder().encode(ciphertext), CHARSET);
            // return ciphertext;
            return strCipherText;
        } catch (NoSuchPaddingException
            | InvalidAlgorithmParameterException
            | ShortBufferException
            | BadPaddingException
            | IllegalBlockSizeException
            | InvalidKeyException
            | NoSuchAlgorithmException
            | UnsupportedEncodingException e) {
            /* None of these exceptions should be possible if precond is met. */
            throw new IllegalStateException(e.toString());
        }
    }

    public static String decrypt_gcm(byte[] ciphertext)
        /* these indicate corrupt or malicious ciphertext */
        /* Note that AEADBadTagException may be thrown in GCM mode; this is a subclass of BadPaddingException */ {
        /* Precond: skey is valid and GCM mode is available in the JRE;
         * otherwise IllegalStateException will be thrown. */
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] initVector = Arrays.copyOfRange(ciphertext, 0, GCM_IV_LENGTH);
            GCMParameterSpec spec =
                new GCMParameterSpec(GCM_TAG_LENGTH * java.lang.Byte.SIZE, initVector);
            cipher.init(Cipher.DECRYPT_MODE, secKey2, spec);
            byte[] plaintext =
                cipher.doFinal(ciphertext, GCM_IV_LENGTH, ciphertext.length - GCM_IV_LENGTH);
            String decryptedText = new String(plaintext);
            LOG.debug("Decrypted text              -> {}", decryptedText);
            return decryptedText;
        } catch (NoSuchPaddingException
            | InvalidAlgorithmParameterException
            | InvalidKeyException
            | BadPaddingException
            | IllegalBlockSizeException
            | NoSuchAlgorithmException e) {
            /* None of these exceptions should be possible if precond is met. */
            throw new IllegalStateException(e.toString());
        }
    }
}
