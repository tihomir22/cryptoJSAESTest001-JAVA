/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package testcrypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.management.openmbean.InvalidKeyException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import static testcrypto.TestCrypto.AesUtil.hex;

/**
 *
 * @author sportak
 */
public class TestCrypto {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, java.security.InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException, InvalidKeySpecException {

        String keyValue = "Abcdefghijklmnop";
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(keyValue.toCharArray(), hex("dc0da04af8fee58593442bf834b30739"),
                1000, 128);

        Key key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(hex("dc0da04af8fee58593442bf834b30739")));

        byte[] encVal = c.doFinal("Visca santaclaus su su su su su susu".getBytes());
        String base64EncodedEncryptedData = new String(Base64.getEncoder().encode(encVal));
        System.out.println(base64EncodedEncryptedData);
    }

    public static class AesUtil {

        private final int keySize;
        private final int iterationCount;
        private final Cipher cipher;

        public AesUtil(int keySize, int iterationCount) {
            this.keySize = keySize;
            this.iterationCount = iterationCount;
            try {
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw fail(e);
            }
        }

        public String decrypt(String salt, String iv, String passphrase, String ciphertext) {
            try {
                SecretKey key = generateKey(salt, passphrase);
                byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, base64(ciphertext));
                return new String(decrypted, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return null;
            } catch (Exception e) {
                return null;
            }
        }

        private byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) {
            try {
                cipher.init(encryptMode, key, new IvParameterSpec(hex(iv)));
                return cipher.doFinal(bytes);
            } catch (java.security.InvalidKeyException ex) {
                Logger.getLogger(TestCrypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(TestCrypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(TestCrypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(TestCrypto.class.getName()).log(Level.SEVERE, null, ex);
            }
            return null;
        }

        private SecretKey generateKey(String salt, String passphrase) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hex(salt), iterationCount, keySize);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
                return key;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                return null;
            }
        }

        public byte[] base64(String str) {
            return Base64.getDecoder().decode(str);
        }

        public static byte[] hex(String str) {
            try {
                return Hex.decodeHex(str.toCharArray());
            } catch (DecoderException e) {
                throw new IllegalStateException(e);
            }
        }

        private IllegalStateException fail(Exception e) {
            return null;
        }
    }

}
