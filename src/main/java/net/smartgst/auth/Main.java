package net.smartgst.auth;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import org.json.JSONObject;

import java.io.InputStream;
import java.util.UUID;

/**
 * Created by gowthaman on 26/11/16.
 */
public class Main {

    public static final String BASE_URL = "http://devapi.gstsystem.co.in";
    public static final String AUTH_PATH = "/taxpayerapi/v0.1/authenticate";

    //random User Name
    public static final String USER_NAME = UUID.randomUUID().toString();
    //random Trx Id
    public static final String TXN = UUID.randomUUID().toString();

    //hard coded state code
    private static final String STATE_CD = "11";

    private static final String CLIENT_ID = "l7xx6df7496552824f15b7f4523c0a1fc114";
    private static final String CLIENT_SECRET = "f328fe52752349c893aa93adcffed8f5";


    //hard coded OTP
    public static final String OTP = "102030";

    //content-type value
    public static final String APPLICATION_JSON = "application/json";
    //hard coded for now
    public static final String IP_USR = "192.168.1.1";

    public static void main(String[] args) throws Exception {
        InputStream pubKeyInpStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("GSTN_PublicKey.cer");

        AESEncryption aesEncryption = new AESEncryption();
        PubKeyEncryption pubKeyEncryption = new PubKeyEncryption(pubKeyInpStream);

        String appKey = aesEncryption.generateSecureKey();

        //get appKey in bytes
        byte[] appKeyInBytes = aesEncryption.decodeBase64StringTOByte(appKey);
        //convert that bytes to an hmac string
        String appKeyEncoded = pubKeyEncryption.generateEncAppkey(appKeyInBytes);

        otpRequest(appKeyEncoded);
        authTokenRequest(appKeyEncoded, aesEncryption.encryptEK(OTP.getBytes(), appKeyInBytes));

    }


    private static void authTokenRequest(String encryptedAppkey, String encryptedOTP) throws Exception {
        JSONObject authTokenReq = new JSONObject();
        authTokenReq.put("action", "AUTHTOKEN");
        authTokenReq.put("appkey", encryptedAppkey);
        authTokenReq.put("username", USER_NAME);
        authTokenReq.put("otp", encryptedOTP);

        HttpResponse<JsonNode> authTokenResp = Unirest.post(String.format("%s/%s", BASE_URL, AUTH_PATH))
                .header("Content-Type", "application/json")
                .header("state-cd", "01")
                .header("clientid", "l7xx6df7496552824f15b7f4523c0a1fc114")
                .header("client-secret", "f328fe52752349c893aa93adcffed8f5")
                .header("ip-usr", "192.168.0.1")
                .header("appkey", encryptedAppkey)
                .header("txn", UUID.randomUUID().toString())
                .body(new JsonNode(authTokenReq.toString()))
                .asJson();

        System.out.println(String.format("AuthToken Request : Status[%s] Response[%s]", authTokenResp.getStatus(), authTokenResp.getBody()));
    }

    private static void otpRequest(String encryptedAppkey) throws Exception {
        JSONObject otpRequest = new JSONObject();
        otpRequest.put("action", "OTPREQUEST");
        otpRequest.put("appkey", encryptedAppkey);
        otpRequest.put("username", USER_NAME);

        HttpResponse<JsonNode> otpResp = Unirest.post(String.format("%s/%s", BASE_URL, AUTH_PATH))
                .header("clientid", CLIENT_ID)
                .header("state-cd", STATE_CD)
                .header("username", USER_NAME)
                .header("txn", TXN)
                .header("appkey", encryptedAppkey)
                .header("client-secret", CLIENT_SECRET)
                .header("ip-usr", IP_USR)
                .header("Content-Type", APPLICATION_JSON)
                .body(new JsonNode(otpRequest.toString()))
                .asJson();

        System.out.println(String.format("OTP Request : Status[%s] Response[%s]", otpResp.getStatus(), otpResp.getBody()));
    }
}
