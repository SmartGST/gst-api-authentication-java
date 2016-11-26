
package net.smartgst.auth;


import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * This class is used to encrypt the string using a
 * public publicKey
 */
public class PubKeyEncryption {


    private PublicKey publicKey;

    public PubKeyEncryption(InputStream pubKeyUrl) throws Exception {
        this.publicKey = readPublicKey(pubKeyUrl);
    }

    private PublicKey readPublicKey(InputStream fin) throws Exception {
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
        return certificate.getPublicKey();

    }

    /**
     * This method is used to encrypt the string , passed to it
     * using a public publicKey provided
     *
     * @param plaintext : Text to encrypt
     * @return :encrypted string
     */
    public String encrypt(byte[] plaintext) throws Exception {


        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedByte = cipher.doFinal(plaintext);
        return new String(java.util.Base64.getEncoder().encode(encryptedByte));
    }

}

