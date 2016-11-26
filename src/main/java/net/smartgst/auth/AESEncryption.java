
package net.smartgst.auth;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;

public class AESEncryption {

    private final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private final String AES_ALGORITHM = "AES";
    private final int ENC_BITS = 256;
    private final String CHARACTER_ENCODING = "UTF-8";

    private Cipher ENCRYPT_CIPHER;
    private Cipher DECRYPT_CIPHER;
    private KeyGenerator KEYGEN;

    public AESEncryption() throws Exception {
        ENCRYPT_CIPHER = Cipher.getInstance(AES_TRANSFORMATION);
        DECRYPT_CIPHER = Cipher.getInstance(AES_TRANSFORMATION);
        KEYGEN = KeyGenerator.getInstance(AES_ALGORITHM);
        KEYGEN.init(ENC_BITS);

    }


    public String encodeBase64String(byte[] bytes) {
        return new String(java.util.Base64.getEncoder().encode(bytes));
    }


    public byte[] decodeBase64StringTOByte(String stringData) throws Exception {
        return java.util.Base64.getDecoder().decode(stringData.getBytes(CHARACTER_ENCODING));
    }


    public String generateSecureKey() throws Exception {
        SecretKey secretKey = KEYGEN.generateKey();
        return encodeBase64String(secretKey.getEncoded());
    }


    public String encryptEK(byte[] plainText, byte[] secret) throws Exception {

        SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
        ENCRYPT_CIPHER.init(Cipher.ENCRYPT_MODE, sk);
        return Base64.encodeBase64String(ENCRYPT_CIPHER
                .doFinal(plainText));


    }


    /**
     * This method is used to decrypt base64 encoded string using an AES 256 bit key.
     *
     * @param plainText : plain text to decrypt
     * @param secret    : key to decrypt
     * @return : Decrypted String
     */
    public byte[] decrypt(String plainText, byte[] secret)
            throws Exception {
        SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
        DECRYPT_CIPHER.init(Cipher.DECRYPT_MODE, sk);
        return DECRYPT_CIPHER.doFinal(Base64.decodeBase64(plainText));
    }


    private void produceSampleData(InputStream pubKeyUrl) throws Exception {
        //Generation of app key. this will be in encoded.
        String appkey = generateSecureKey();
        System.out.println("App key in encoded : " + appkey);
        //Encrypt with GSTN public key
        String encryptedAppkey = new PubKeyEncryption(pubKeyUrl).generateEncAppkey(decodeBase64StringTOByte(appkey));
        System.out.println("Encrypted App Key ->" + encryptedAppkey);


        //Generation of OTP with appkey
        String otp = "102030";
        String encryptedOtp = encryptEK(otp.getBytes(), decodeBase64StringTOByte(appkey));
        System.out.println("OTP :" + encryptedOtp);


    }

    public void testData() throws Exception {


        String decrypted_appkey = "41+sD/gm9DWQeZbJm98qb3ss9Eu96XkClU5a4hyfaAw=";
        String receivedSEK = "yDWrI0m6juY+MKsPNtWkBYJAVsE0XIQvAJwv+P2T9DgOLzbTmU1E5NkewRcnIsK2";
        String gotREK = "QdwtOmbHgs5+T6XguaXrJtXyc1EpapQzuV5wWgEiDbUdShGCyOtl6JelLUI/R5xt";
        String data = "czI9UduToC0S2M/Z8NxmD6AaiCHqK/wN4cLnpjje1LCgo7hXhoGvSUac0BB9umkBnWEO+osui4ZZHZIHrO8bvMlQI5mmyuqDxqLTg5IkgYCzUnDWGV6qP/6ei2J8eCKLxqv0XALN228h0QhNK4nr3Q9n4HVGngdXJf1dSIcxNVXQaJTctti1w7n6bm5Ht2FlMVKsIT7O8bwD9OyJtV0Z0jZa45DoWMxIwbRQKTnBCzC7+gCWSBriGW1Bsc4AGMzQks8qE0y1rQscgtPp8D6/eHjIT5e3jwn9EWYZdgDb+y1sCaUL77AEvKm9inM3fyfj3yw11I31NX79KVFzKCOFA3gfuz2RhTZ5QnxuUABGuHXDrLKaYkkxa6f0GPBDJmUqs5/R1w2YjpOzdDG+i0zRjPvIdSpM4wzVt0dB449TplAftdPkLCmVKBovrLe8OwE58nI5j63Kr8JMFc/V8XBFDpRDZl4EgdLeKWX4rop67GeWUVjdIyyAuiOiXTi/v9r1EGpFzybDJE2Z9S2/ntK5iVsPT6Bn4MaqkTiOG5D3eh5aDNuM3mToDC6LSD7PkX9Ekt1R/T1dLeKDOnEo5aQqCcqm/v5A9AZw86nyzFPfdjLfl9TOem4/hSP8Xslx645jnhUlr3kkshw5LzRpx5KaC32PC+eOcRq6MEeVF6vStvA/XA/9dRazxwvPnS4z09gtSdZRozls1UmNjBkhSoh4tDSU0lQXIsrmr/tGtLSsj1fH7h5De+qBvhyvY3LOw6CGfq3dKUFcE0n4yLosMIm2xbtVzROGdNXgDmUPUmk9wXHLc5UA8GNY9rq1z1ypCBbYpHLCQ9NHLncweF2FOK2obqF3kioypUbPxndgtd4cbVReXf9XBL9YkkxDCvNjH44bz0ciVnhg9jwGETLU6z40/s3ew8dDrNCbUmrGK42YxB44Ljwk5RQBRa5uMJnrFKiR8dnUJZai12moHO6GzIg5yiYEEa65rbzgdJOozcjTXgLl2Mf1uR4jN3Y7+u/e4OcYNHlF2Jd/7EGH+sJ9aOIYsq0K8f82o4jbbInhSg37pv2Kf5fm6urd4UoQUJ01fGGOHytSegKX2wO9vlKhHyrbu1+zMnfjEXabjENTlLWS5npkDhO7CaVsK4XsxTucsSdXKg3w7n82C05acOwrvewHCMNWD1IZuuKKcHWLhd7khs0gGRSQR4eKbN17fuYg2aTkQM/n1/8/NZP35UsMt+w9zpewE1wQr6C4guFoiIS1IUReJwFqCBAHsyXCnSdVjZlzZu40KYGWjR3TmkG4vVZA22cxsq83Oc/aykrflL0f1QI6txyfqSZAlpNEqKHerDR/iGAgwYa5f9y8Id7hnyK1lU0NnkAbKbBh9GWuvtBiNL7AvrDNMLt2lStyuDhh0TTscAqFv26jjAtz2MoEZ9HPvoBPDAsxq0HGFeoypyeQKZI0/xTh+iVcsMxgqY5FeOEiWEW/cBBJZOP402+319jDlDoSRerbUKwP63TLxE/zL2j4YyxHTEWi9PUiF+JosUHmza9PiyTdbIxyrhxXDfKVoQ==";


        byte[] authEK = decrypt(receivedSEK, decodeBase64StringTOByte(decrypted_appkey));
        System.out.println("Encoded Auth EK (Received):" + encodeBase64String(authEK));

        byte[] apiEK = decrypt(gotREK, authEK);
        System.out.println("Encoded Api EK (Received):" + encodeBase64String(apiEK));
        String jsonData = new String(decodeBase64StringTOByte(new String(decrypt(data, apiEK))));
        System.out.println(jsonData);


    }

    public static void main(String args[]) throws Exception {
        InputStream pubKeyInpStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("GSTN_PublicKey.cer");
        AESEncryption aesEncryption = new AESEncryption();
        //aesEncryption.produceSampleData(pubKeyInpStream);
        aesEncryption.testData();

    }
}
