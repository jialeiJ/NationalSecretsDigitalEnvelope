package com.vienna.jaray.utils;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import com.alibaba.fastjson.JSONObject;
import com.vienna.jaray.constant.HashAlgorithmType;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 解析、封装前端参数工具类
 */
@Slf4j
@Component
public class ParsePackageParamsUtil {


    /**
     * 校验请求数据合法性
     * @param ciphertext 加密的密文
     * @param key 用于对称加密，sys公钥加密的key
     * @param iv 用于对称加密，sys公钥加密的kiv
     * @param hash hash值，明文的sha256的hash并进行对称加密
     * @param sign sign值，ui公钥对hash的签名
     * @return
     */
    public boolean VerifyDataLegality(String ciphertext, String key, String iv, String hash, String sign){
        //创建sm2 对象
        SM2 sm2 = Sm2Util.getPriSm2ByPrivateKey(Sm2Util.sysPrivateKey);

        // 私钥解密
        String realKey = StrUtil.utf8Str(sm2.decryptFromBcd(key, KeyType.PrivateKey));
        String realIv = StrUtil.utf8Str(sm2.decryptFromBcd(iv, KeyType.PrivateKey));

        log.debug("数字信封 待解密的密文：{} key：{} iv：{}", ciphertext, realKey, realIv);

        // 公钥验签
        boolean verify = Sm2Util.verify(Sm2Util.uiPublicKey, hash, sign);
        log.debug("数字信封 签名验签结果={}", verify);
        if (!verify) {
            return verify;
        }


        String desData = CryptoUtil.decrypt(ciphertext, realKey, realIv);
        String encData = CryptoUtil.encrypt(desData, realKey, realIv);
        log.debug("数字信封 解密后的信息：{} 再次加密数据：{}", desData, encData);

        String calHashValue = HashUtil.hexHashOfStr(desData, HashAlgorithmType.SHA256.getName());
        String reqHashvalue = CryptoUtil.decrypt(hash, realKey, realIv);

        log.debug("数字信封 后端计算的信息摘要={} 解密出来的信息摘要={}", calHashValue, reqHashvalue);

        return StringUtils.equalsIgnoreCase(calHashValue, reqHashvalue);
    }

    /**
     * 解析密文
     * @param ciphertext 密文
     * @param key 公钥加密后的key
     * @param iv 公钥加密后的iv
     * @return
     */
    public String parseFrontData(String ciphertext, String key, String iv){
        //创建 sm2 对象
        SM2 sm2 = Sm2Util.getPriSm2ByPrivateKey(Sm2Util.sysPrivateKey);

        // 私钥解密
        String realKey = StrUtil.utf8Str(sm2.decryptFromBcd(key, KeyType.PrivateKey));
        String realIv = StrUtil.utf8Str(sm2.decryptFromBcd(iv, KeyType.PrivateKey));
        log.debug("数字信封 待解密的密文：{} key：{} iv：{}", ciphertext, realKey, realIv);

        String desData = CryptoUtil.decrypt(ciphertext, realKey, realIv);
        log.debug("数字信封 解密后的前端信息={}", desData);

        return desData;
    }


    /**
     * 封装响应数据
     * @param responseStr
     * @return
     */
    public String packageResponseData(String responseStr){
        // 生成随机对称秘钥key、iv
        String keyStr = CryptoUtil.generateKeyOrIv(16);
        String ivStr = CryptoUtil.generateKeyOrIv(16);

        // 使用sm2(非对称密钥)加密key、iv
        String key = Sm2Util.encrypt(keyStr, Sm2Util.uiPublicKey);
        String iv = Sm2Util.encrypt(ivStr, Sm2Util.uiPublicKey);

        // 生成明文的信息摘要md5
        String sha256HexHash = HashUtil.hexHashOfStr(responseStr, HashAlgorithmType.SHA256.getName());
        String hash = CryptoUtil.encrypt(sha256HexHash, keyStr, ivStr);
        log.debug("数字信封 响应 加密的信息摘要：{}", hash);

        String sign = Sm2Util.sign(Sm2Util.sysPrivateKey, hash);
        boolean verify = Sm2Util.verify(Sm2Util.sysPubliceKey, hash, sign);
        log.debug("数字信封 响应 验签结果：{}", verify);

        Map<String, String> resMap = new HashMap<>();
        resMap.put("key", key);
        resMap.put("iv", iv);
        resMap.put("hash", hash);
        resMap.put("sign", sign);
        resMap.put("ciphertext", CryptoUtil.encrypt(responseStr, keyStr, ivStr));

        return JSONObject.toJSONString(resMap);
    }


    /**
     * 国密校验请求数据合法性
     * @param ciphertext 加密的密文
     * @param key 用于对称加密，sys公钥加密的key
     * @param iv 用于对称加密，sys公钥加密的kiv
     * @param hash hash值，明文的sha256的hash并进行对称加密
     * @param sign sign值，ui公钥对hash的签名
     * @return
     */
    public boolean VerifyDataLegalityForNationalSecrets(String ciphertext, String key, String iv, String hash, String sign){
        //创建sm2 对象
        SM2 sm2 = Sm2Util.getPriSm2ByPrivateKey(Sm2Util.sysPrivateKey);

        // 私钥解密
        String realKey = StrUtil.utf8Str(sm2.decryptFromBcd(key, KeyType.PrivateKey));
        String realIv = StrUtil.utf8Str(sm2.decryptFromBcd(iv, KeyType.PrivateKey));
        log.debug("国密数字信封 待解密的密文：{} key：{} iv：{}", ciphertext, realKey, realIv);

        // 公钥验签
        boolean verify = Sm2Util.verify(Sm2Util.uiPublicKey, hash, sign);
        log.debug("国密数字信封 签名验签结果={}", verify);
        if (!verify) {
            return verify;
        }


        String desData = Sm4Util.decrypt(ciphertext, realKey, realIv);
        String encData = Sm4Util.encrypt(desData, realKey, realIv);
        log.debug("国密数字信封 解密后的信息={} 再次加密数据={}", desData, encData);

        String calHashValue = Sm3Util.getSm3DataByString(desData);
        String reqHashvalue = Sm4Util.decrypt(hash, realKey, realIv);

        log.debug("国密数字信封 后端计算的信息摘要={} 解密出来的信息摘要={}", calHashValue, reqHashvalue);

        return StringUtils.equalsIgnoreCase(calHashValue, reqHashvalue);
    }


    /**
     * 国密解析密文
     * @param ciphertext 密文
     * @param key 公钥加密后的key
     * @param iv 公钥加密后的iv
     * @return
     */
    public String parseFrontDataForNationalSecrets(String ciphertext, String key, String iv){
        //创建 sm2 对象
        SM2 sm2 = Sm2Util.getPriSm2ByPrivateKey(Sm2Util.sysPrivateKey);

        // 私钥解密
        String realKey = StrUtil.utf8Str(sm2.decryptFromBcd(key, KeyType.PrivateKey));
        String realIv = StrUtil.utf8Str(sm2.decryptFromBcd(iv, KeyType.PrivateKey));
        log.debug("国密数字信封 待解密的密文：{} key：{} iv：{}", ciphertext, realKey, realIv);

        String desData = Sm4Util.decrypt(ciphertext, realKey, realIv);
        log.debug("国密数字信封 解密后的前端信息={}", desData);

        return desData;
    }


    public String packageResponseDataForNationalSecrets(String responseStr){

        // 生成随机对称秘钥key、iv
        String keyStr = Sm4Util.generateKeyOrIv(32);
        String ivStr = Sm4Util.generateKeyOrIv(32);

        // 使用sm2(非对称密钥)加密key、iv
        String key = Sm2Util.encrypt(keyStr, Sm2Util.uiPublicKey);
        String iv = Sm2Util.encrypt(ivStr, Sm2Util.uiPublicKey);

        // 生成明文的信息摘要md5
        String realHash = Sm3Util.getSm3DataByString(responseStr);
        String hash = Sm4Util.encrypt(realHash, keyStr, ivStr);
        log.debug("国密数字信封 响应 加密的信息摘要：{}", hash);

        String sign = Sm2Util.sign(Sm2Util.sysPrivateKey, hash);
        boolean verify = Sm2Util.verify(Sm2Util.sysPubliceKey, hash, sign);
        log.debug("国密数字信封 响应 验签结果：{}", verify);

        Map<String, String> resMap = new HashMap<>();
        resMap.put("key", key);
        resMap.put("iv", iv);
        resMap.put("hash", hash);
        resMap.put("sign", sign);
        resMap.put("ciphertext", Sm4Util.encrypt(responseStr, keyStr, ivStr));

        return JSONObject.toJSONString(resMap);
    }
}
