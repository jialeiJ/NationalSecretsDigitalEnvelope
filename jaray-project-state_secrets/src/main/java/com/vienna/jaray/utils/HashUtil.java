package com.vienna.jaray.utils;

import com.vienna.jaray.constant.HashAlgorithmType;
import lombok.extern.slf4j.Slf4j;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class HashUtil {

    public String hexHashOfFileMd5(File file){
        return toHex(HashAlgorithmType.MD5.checksum(file));
    }

    public String hexHashOfFileSha1(File file){
        return toHex(HashAlgorithmType.SHA1.checksum(file));
    }

    public String hexHashOfFileSha256(File file){
        return toHex(HashAlgorithmType.SHA256.checksum(file));
    }

    public String hexHashOfFileSha512(File file){
        return toHex(HashAlgorithmType.SHA512.checksum(file));
    }

    private static String toHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes).toUpperCase();
    }


    /**
     * 计算hash
     * @param data
     * @param instanceType MD5、SHA-1、SHA-256、SHA-512
     * @return
     */
    public static String hexHashOfStr(String data, String instanceType){
        try {
            // 为MD5创建MessageDigest实例
            MessageDigest md = MessageDigest.getInstance(instanceType);
            //添加密码字节以进行
            md.update(data.getBytes());
            //Get the hash's bytes
            byte[] bytes = md.digest();
            //This bytes[] has bytes in decimal format;
            //将其转换为十六进制格式
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            //得到完整的哈希密码在十六进制格式
            return sb.toString().toUpperCase();
        }
        catch (NoSuchAlgorithmException e) {
            log.error("未找到算法异常：{}", e);
        }
        return null;
    }
}
