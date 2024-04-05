package com.vienna.jaray.utils;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.digest.SM3;
import lombok.extern.slf4j.Slf4j;

import java.io.UnsupportedEncodingException;

/**
 * 国密Sm3, 计算hash
 */
@Slf4j
public class Sm3Util {


    /**
     * SM3 hash算法
     */
    public static String getSm3DataByString(String data) {
        String digest = SmUtil.sm3(data);
        log.debug("国密数字信封 计算的hash摘要：{} data：{}", digest, data);
        return digest;
    }

    /**
     * SM3 hash算法
     */
    public static void sm3Test() {
        String text = "I am Jaray";
        String digestHex = SmUtil.sm3(text);
        System.out.println("计算的hash摘要：" + digestHex);


        SM3 sm3 = SmUtil.sm3();
        System.out.println("计算的hash摘要：" + sm3.digestHex(text));
    }


    public static void main(String[] args) throws UnsupportedEncodingException {
        new Sm3Util().sm3Test();
    }
}
