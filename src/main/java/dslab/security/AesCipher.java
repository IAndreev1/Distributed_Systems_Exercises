package dslab.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class AesCipher {

    private static final Log LOG = LogFactory.getLog(AesCipher.class);
    private final static String TRANSFORMATION = "AES/CTR/NoPadding";
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private final Cipher encrypter;
    private final Cipher decrypter;
    private final Base64.Encoder encoder;
    private final Base64.Decoder decoder;

    public AesCipher(Key key, byte[] iv) throws
            InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        encrypter = Cipher.getInstance(TRANSFORMATION);
        encrypter.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        decrypter = Cipher.getInstance(TRANSFORMATION);
        decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
    }

    public String encrypt(String plain) {
        try {
            byte[] bytes = encrypter.doFinal(plain.getBytes(UTF_8));
            return encoder.encodeToString(bytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            LOG.error("Encryption error: " + e.getMessage(), e);
            return null;
        }
    }

    public String decrypt(String encrypted) {
        try {
            byte[] bytes = decrypter.doFinal(decoder.decode(encrypted));
            return new String(bytes, UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            LOG.error("Decryption error: " + e.getMessage(), e);
            return null;
        }
    }
}
