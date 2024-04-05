package com.vienna.jaray.utils;

import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.BCUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * 国密Sm2，非对称加密，用于加密key、iv,加签验签工具类
 */
@Slf4j
public class Sm2Util {

    public static final String uiPrivateKey = "00ee2093b01888f1a65fef233404981f62087933eb9be969e3c64b442a7304127a";
    public static final String uiPublicKey = "04cef5a9860af217790cecdbb2b5af5aaa1d472bf9cd69bed2d0fd562c2d93a0db151f289a920314755d0fe27b17a55a8a4a55e3d093b465e2a631540d4bbf2033";
    public static final String sysPrivateKey = "559f2f680d350c9732dc196a92fb009d5ce013dca3b431dff42ffc5c0d50e179";
    public static final String sysPubliceKey = "04b8ad10bb99367037dde9e836eb82655460e51761748cb2e525dea1bc09bfd7011c86c60a200cae237ff95c98e996094563e1bcaa7b54263c70ef48d48a5b3ed3";


    /**
     * 通过私钥获取Sm2，用于解密
     * @param privateKey 私钥
     * @return
     */
    public static SM2 getPriSm2ByPrivateKey(String privateKey) {

        //这里需要根据公钥的长度进行加工
        if (privateKey.length() == 66) {
            //这里需要去掉开始第一个字节 第一个字节表示标记
            privateKey = privateKey.substring(2);
        }
        ECPrivateKeyParameters ecPrivateKeyParameters = BCUtil.toSm2Params(privateKey);
        //创建sm2 对象
        SM2 sm2 = new SM2(ecPrivateKeyParameters, null);
        //这里需要手动设置，sm2 对象的默认值与我们期望的不一致 , 使用明文编码
        sm2.usePlainEncoding();
        sm2.setMode(SM2Engine.Mode.C1C2C3);
        return sm2;
    }

    /**
     * 通过公钥获取Sm2，用于加密
     * @param publicKey
     * @return
     */
    public static SM2 getPubSm2ByPublicKey(String publicKey) {
        ECPublicKeyParameters ecPublicKeyParameters = null;
        //这里需要根据公钥的长度进行加工
        if (publicKey.length() == 130) {
            //这里需要去掉开始第一个字节 第一个字节表示标记
            publicKey = publicKey.substring(2);
            String xhex = publicKey.substring(0, 64);
            String yhex = publicKey.substring(64, 128);
            ecPublicKeyParameters = BCUtil.toSm2Params(xhex, yhex);
        } else {
            PublicKey p = BCUtil.decodeECPoint(publicKey, SmUtil.SM2_CURVE_NAME);
            ecPublicKeyParameters = BCUtil.toParams(p);
        }
        //创建sm2 对象
        SM2 sm2 = new SM2(null, ecPublicKeyParameters);
        sm2.usePlainEncoding();
        sm2.setMode(SM2Engine.Mode.C1C2C3);
        return sm2;
    }


    /**
     * Sm2公钥加密
     * @param plaintext  明文
     * @param publicKey  公钥
     * @return
     */
    public static String encrypt(String plaintext, String publicKey) {
        ECPublicKeyParameters ecPublicKeyParameters = null;
        //这里需要根据公钥的长度进行加工
        if (publicKey.length() == 130) {
            //这里需要去掉开始第一个字节 第一个字节表示标记
            publicKey = publicKey.substring(2);
            String xhex = publicKey.substring(0, 64);
            String yhex = publicKey.substring(64, 128);
            ecPublicKeyParameters = BCUtil.toSm2Params(xhex, yhex);
        } else {
            PublicKey p = BCUtil.decodeECPoint(publicKey, SmUtil.SM2_CURVE_NAME);
            ecPublicKeyParameters = BCUtil.toParams(p);
        }
        //创建sm2 对象
        SM2 sm2 = new SM2(null, ecPublicKeyParameters);
        sm2.usePlainEncoding();
        sm2.setMode(SM2Engine.Mode.C1C2C3);

        return sm2.encryptBcd(plaintext, KeyType.PublicKey);
    }




    /**
     * 验证签名
     * @param publicKey     公钥
     * @param data          签名内容
     * @param sign          签名值
     * @return
     */
    public static boolean verify(String publicKey, String data, String sign) {
        ECPublicKeyParameters ecPublicKeyParameters = null;
        //这里需要根据公钥的长度进行加工
        if (publicKey.length() == 130) {
            //这里需要去掉开始第一个字节 第一个字节表示标记
            publicKey = publicKey.substring(2);
            String xhex = publicKey.substring(0, 64);
            String yhex = publicKey.substring(64, 128);
            ecPublicKeyParameters = BCUtil.toSm2Params(xhex, yhex);
        } else {
            PublicKey p = BCUtil.decodeECPoint(publicKey, SmUtil.SM2_CURVE_NAME);
            ecPublicKeyParameters = BCUtil.toParams(p);
        }
        //创建sm2对象, 不能使用SM2 sm2 = HutoolSMUtil.getPubSm2ByPublicKey(publicKey); 验签不能设置sm2.setMode(SM2Engine.Mode.C1C2C3);
        SM2 sm2 = new SM2(null, ecPublicKeyParameters);

        boolean verify = sm2.verify(data.getBytes(), HexUtil.decodeHex(sign));
        return verify;
    }


    /**
     * 私钥签名
     * @param privateKey  系统私钥
     * @param content     待签名内容
     * @return
     */
    public static String sign(String privateKey, String content) {
        //这里需要根据公钥的长度进行加工
        if (privateKey.length() == 66) {
            //这里需要去掉开始第一个字节 第一个字节表示标记
            privateKey = privateKey.substring(2);
        }
        ECPrivateKeyParameters ecPrivateKeyParameters = BCUtil.toSm2Params(privateKey);
        //创建sm2 对象
        SM2 sm2 = new SM2(ecPrivateKeyParameters, null);
        String sign = HexUtil.encodeHexStr(sm2.sign(content.getBytes()));
        return sign;
    }


    /**
     * SM2非对称加密
     */
    public void sm2Test() throws UnsupportedEncodingException {

        String text = "wangjing";

        //使用随机生成的密钥对加密或解密
        System.out.println("使用随机生成的密钥对加密或解密====开始");
        SM2 sm2 = SmUtil.sm2();
        // 公钥加密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        System.out.println("公钥加密：" + encryptStr);
        //私钥解密
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("私钥解密：" + decryptStr);
        System.out.println("使用随机生成的密钥对加密或解密====结束");


        //使用自定义密钥对加密或解密
        System.out.println("使用自定义密钥对加密或解密====开始");

        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();


        //这里会自动生成对应的随机秘钥对 , 注意！ 这里一定要强转，才能得到对应有效的秘钥信息
        byte[] privateKeyByte = BCUtil.encodeECPrivateKey(sm2.getPrivateKey());
        //这里公钥不压缩  公钥的第一个字节用于表示是否压缩  可以不要
        byte[] publicKeyByte = ((BCECPublicKey) sm2.getPublicKey()).getQ().getEncoded(false);
        //这里得到的 压缩后的公钥   ((BCECPublicKey) sm2.getPublicKey()).getQ().getEncoded(true);
        // byte[] publicKeyEc = BCUtil.encodeECPublicKey(sm2.getPublicKey());
        //打印当前的公私秘钥
        System.out.println("私钥: " + HexUtil.encodeHexStr(privateKeyByte));
        System.out.println("公钥: " + HexUtil.encodeHexStr(publicKeyByte));


        SM2 sm22 = SmUtil.sm2(privateKey, publicKey);
        // 公钥加密
        String encryptStr2 = sm22.encryptBcd(text, KeyType.PublicKey);
        System.out.println("公钥加密：" + encryptStr2);
        //私钥解密
        String decryptStr2 = StrUtil.utf8Str(sm22.decryptFromBcd(encryptStr2, KeyType.PrivateKey));
        System.out.println("私钥解密：" + decryptStr2);
        System.out.println("使用自定义密钥对加密或解密====结束");


        String content = "我是Hanley.";
        KeyPair pairr = SecureUtil.generateKeyPair("SM2");
        final SM2 sm222 = new SM2(pairr.getPrivate(), pairr.getPublic());
        byte[] sign = sm222.sign(content.getBytes());
        // true
        boolean verify = sm222.verify(content.getBytes(), sign);

        System.out.println("验签===" + verify);
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        new Sm2Util().sm2Test();
//        System.out.println("-------------------------------------------------------");
//        new HutoolSMUtil().sm3Test();
//        System.out.println("-------------------------------------------------------");
//        new HutoolSMUtil().sm4Test();
    }
}
