import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * created by george on 2018/5/11 下午2:09
 *
 * @author george
 * @version 1.0
 * @since 1.0
 */
public class RSAUtil {

	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	/**
	 * 用私钥对信息生成数字签名
	 *
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            私钥
	 *
	 * @return 数字签名
	 * @throws Exception 加密异常
	 */
	/*public static String sign(byte[] data, String privateKey) throws Exception {
		// 解密由base64编码的私钥
		byte[] keyBytes = decryptBASE64(privateKey);

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);

		return encryptBASE64(signature.sign());
	}*/

	/**
	 * 校验数字签名
	 *
	 * @param data
	 *            加密数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 *
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception 解密异常
	 *
	 */
	public static boolean verify(byte[] data, String publicKey, String sign)
			throws Exception {

		// 解密由base64编码的公钥
		byte[] keyBytes = decryptBASE64(publicKey);

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);

		// 验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}

	/**
	 * BASE64解密
	 *
	 * @param key
	 * @return BASE解密后的byte数组
	 * @throws Exception 解密异常
	 */
	public static byte[] decryptBASE64(String key) throws Exception {
		return (new BASE64Decoder()).decodeBuffer(key);
	}

	/**
	 * BASE64加密
	 *
	 * @return 返回BASE64加密字符串
	 * @throws Exception 加密异常
	 */
/*
	public static String encryptBASE64(byte[] key) throws Exception {
		return (new BASE64Encoder()).encodeBuffer(key);
	}
*/

	public static void main(String[] args) throws Exception {
		String phoneNo = "18912345678";
		String timestamp = "1526030823511";
		String encyptPhoneNo = MD5SignUtil.md5Direct(phoneNo);

		//String data = "name=&phoneNo=" + encyptPhoneNo + "&timestamp=" + timestamp;
		String data = "test123";

		String privateKey = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAmXug8cAahQfFpHYGe3K9gHsBvhnD\n" +
				"VlfR+SkfVQ8pLFEeQGWu7C0xKLNgzkBKP8A9y9j+Zoyv1irPRJvasgR3uwIDAQABAkAN6AezH8bH\n" +
				"Wubrec4ojULiS0LjKI5sWlSqELHIETGX1DXPrkx61AojZGFdO+4rINkXgix5sQAkeExlWml8EMph\n" +
				"AiEAx4gOPVfATGBm7AWS74geXFaA0ONegSJy1i5oUJnHm/MCIQDE62Gyi1lzmCnC63S7EgmvbtK0\n" +
				"BzZhgs95k3NPLtEPGQIhAJQJ7ga1RIdmPvZ+bDYr19rKk2hoSYWl+W3PoLWsYtzhAiAWwGtlSZxo\n" +
				"MqiAkNvH0Wm1D0Tg8ARkd8yo61RjTbFx4QIgAzEzc/MYJubgOqjGB91Bo/GIWyx1NEmBstdA3G5W\n" +
				"f08=";
		String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJl7oPHAGoUHxaR2BntyvYB7Ab4Zw1ZX0fkpH1UPKSxR\n" +
				"HkBlruwtMSizYM5ASj/APcvY/maMr9Yqz0Sb2rIEd7sCAwEAAQ==";

		String sign = null;
		System.out.println("签名==");
		System.out.println(sign);

		String sign2 = "JQgsIKUK0SMGdMAfw/8LVLjLVVSZuSiowXEa3jPjLHkgI2xcZowJbjAe3P6AAuTmJG3xubf4CgmO\n" +
				"iyF9Ov66cQ==";
		System.out.println(sign.equals(sign2));

		boolean flag = verify(data.getBytes(), publicKey, sign);

		System.out.println("验签结果:" + flag);
	}
}
