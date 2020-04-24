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

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class SecurityUtilTest {

    @Test
    public void encryptDecryptAES128_gcm() {
        String data = "decrypt SUCCESS!!";
        String encrypted = SecurityUtil.INSTANCE.encrypt_gcm(data);
        assertNotEquals( data, encrypted );
        byte[] decryptMsg = Base64.getDecoder().decode(encrypted);
        assertEquals( SecurityUtil.INSTANCE.decrypt_gcm( decryptMsg), data);
        assertEquals( SecurityUtil.INSTANCE.decrypt_gcm( encrypted.getBytes()), data );
    }

    @Test
    public void obfuscateKey() {
        String key = "abcdefghij123456";
        String expectedkey = "********ij123456";
        String obfuscated = SecurityUtil.INSTANCE.obfuscateKey( key );
        System.out.println( obfuscated );
        assertEquals( obfuscated , expectedkey );
    }
}