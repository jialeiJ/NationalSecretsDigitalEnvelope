package com.vienna.jaray.utils;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SM4;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import lombok.extern.slf4j.Slf4j;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

/**
 * 国密Sm4,对称加密工具类
 */
@Slf4j
public class Sm4Util {

    private static String key = "41bAdd3B3E553d4De36bb2aA19ab9bc4";
    private static String iv = "bAccFEafbEb1Ddf6F9af8b01e22FFee4";


    /**
     * SM4 对称加密
     */
    public static String encrypt(String plaintext, String key, String iv) {
        SM4 sm4 = new SM4(Mode.CBC.name(), Padding.PKCS5Padding.name(), HexUtil.decodeHex(key), HexUtil.decodeHex(iv));
        String ciphertext = sm4.encryptHex(plaintext);
        log.debug("国密数字信封 plaintext：{} key：{} iv：{}", ciphertext, key, iv);
        log.debug("国密数字信封  加密后：{}", ciphertext);
        return ciphertext;
    }

    /**
     * SM4 对称解密
     */
    public static String decrypt(String ciphertext, String key, String iv) {
        SM4 sm4 = new SM4(Mode.CBC.name(), Padding.PKCS5Padding.name(), HexUtil.decodeHex(key), HexUtil.decodeHex(iv));
        String plaintext = sm4.decryptStr(ciphertext, CharsetUtil.CHARSET_UTF_8);
        log.debug("国密数字信封 ciphertext：{} key：{} iv：{}", ciphertext, key, iv);
        log.debug("国密数字信封  解密后：{}", plaintext);
        return plaintext;
    }


    /**
     * 生成key及iv
     * @param num
     * @return
     */
    public static String generateKeyOrIv(int num) {
        String library = "ABCDEFabcdef0123456789";
        String key = "";
        Random random = new Random();
        for (int i = 0; i < num; i++) {
            int index = random.nextInt(library.length());
            key += library.charAt(index);
        }
        return key;
    }


    /**
     * SM4 对称加密
     */
    public void sm4Test() {
        key = "41bAdd3B3E553d4De36bb2aA19ab9bc4";
        iv = "bAccFEafbEb1Ddf6F9af8b01e22FFee4";
        String text = "I am Jaray";
        SM4 sm4 = new SM4(Mode.CBC.name(), Padding.PKCS5Padding.name(), HexUtil.decodeHex(key), HexUtil.decodeHex(iv));

        sm4.setIv(HexUtil.decodeHex(iv));
        String encryptHex = sm4.encryptHex(text);
        System.out.println("加密后：" + encryptHex);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        System.out.println("解密后：" + decryptStr);



        sm4 = new SM4(Mode.CBC.name(), Padding.PKCS5Padding.name(), HexUtil.decodeHex(key), HexUtil.decodeHex(iv));
        decryptStr = sm4.decryptStr(HexUtil.decodeHex("6081a492040819d51ba0131755a321f4"));
        System.out.println("适配前端解密后：" + decryptStr);
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        new Sm4Util().sm4Test();
    }
}
