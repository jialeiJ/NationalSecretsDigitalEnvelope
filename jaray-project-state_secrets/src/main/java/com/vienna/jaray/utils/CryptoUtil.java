package com.vienna.jaray.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

@Slf4j
public class CryptoUtil {

    /***
     * key和iv值需要和前端一致
     */
    public static final String KEY = "smLeGV63judEcxKU";
    public static final String IV = "lFbGSVuAmZqtPCLa";

    private CryptoUtil() {
    }

    /**
     * 生成key及iv
     * @param num
     * @return
     */
    public static String generateKeyOrIv(int num) {
        String library = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        String key = "";
        Random random = new Random();
        for (int i = 0; i < num; i++) {
            int index = random.nextInt(library.length());
            key += library.charAt(index);
        }
        return key;
    }

    /**
     * 对称加密方法
     *
     * @param data 要加密的数据
     * @param key  key
     * @param iv   iv
     * @return 加密的结果（加密失败返回null）
     */
    public static String encrypt(String data, String key, String iv) {
        try {
            //"算法/模式/补码方式"NoPadding PkcsPadding
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            int blockSize = cipher.getBlockSize();

            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }

            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(iv.getBytes()));

            byte[] encrypted = cipher.doFinal(plaintext);
            return new Base64().encodeToString(encrypted);
        } catch (Exception e) {
            log.error("AES加密异常：{}", e);
            return null;
        }
    }

    /**
     * 对称解密方法
     *
     * @param data 要解密的数据
     * @param key  key
     * @param iv   iv
     * @return 解密的结果（解密失败返回原始值）
     */
    public static String decrypt(String data, String key, String iv) {
        try {
            byte[] encrypted = new Base64().decode(data);

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(iv.getBytes()));
            byte[] original = cipher.doFinal(encrypted);
            return new String(original).trim();
        } catch (Exception e) {
            log.error("AES解密异常", e);
            return null;
        }
    }
}
