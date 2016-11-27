package net.smartgst.auth;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import org.json.JSONObject;

import java.io.InputStream;
import java.util.Objects;
import java.util.UUID;

/**
 * Created by gowthaman on 26/11/16.
 */
public class GSTAuth {

    public static final String AUTHTOKEN = "AUTHTOKEN";
    public static final String OTPREQUEST = "OTPREQUEST";
    private final String userName;
    private final String appKey;
    private final byte[] appKeyInBytes;
    private final String appKeyEncryptedAndCoded;
    private String clientId;
    private String clientSecret;
    private String state;
    private String ipAddr;
    private String txn;

    private static final String BASE_URL = "http://devapi.gstsystem.co.in";
    private static final String AUTH_PATH = "/taxpayerapi/v0.1/authenticate";

    //content-type value
    private static final String APPLICATION_JSON = "application/json";

    private PubKeyEncryption pubKeyEncryption;
    private AESEncryption aesEncryption;
    private String authToken;
    private byte[] authSEK;

    public PubKeyEncryption getPubKeyEncryption() {
        return pubKeyEncryption;
    }

    public AESEncryption getAesEncryption() {
        return aesEncryption;
    }

    public byte[] getAuthSEK() {
        return authSEK;
    }

    public String getAppKey() {
        return appKey;
    }

    public byte[] getAppKeyInBytes() {
        return appKeyInBytes;
    }

    public String getAppKeyEncryptedAndCoded() {
        return appKeyEncryptedAndCoded;
    }

    public String getAuthToken() {
        return authToken;
    }

    public GSTAuth(String clientId, String clientSecret, String userName, String state,
                   String ipAddr, String txn, InputStream pubKeyInpStream) throws Exception {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.userName = userName;
        this.state = state;
        this.ipAddr = ipAddr;
        this.txn = txn;
        aesEncryption = new AESEncryption();
        pubKeyEncryption = new PubKeyEncryption(pubKeyInpStream);

        this.appKey = aesEncryption.generateSecureKey();

        //get appKey in bytes
        this.appKeyInBytes = aesEncryption.decodeBase64StringTOByte(appKey);
        //convert that bytes to an hmac string
        this.appKeyEncryptedAndCoded = pubKeyEncryption.encrypt(appKeyInBytes);
    }


    public boolean authTokenRequest(String otp) throws Exception {

        String encryptedOTP = aesEncryption.encryptEK(otp.getBytes(), appKeyInBytes);

        JSONObject authTokenReq = new JSONObject();
        authTokenReq.put("action", AUTHTOKEN);
        authTokenReq.put("appkey", appKeyEncryptedAndCoded);
        authTokenReq.put("username", userName);
        authTokenReq.put("otp", encryptedOTP);

        HttpResponse<JsonNode> authTokenResp = Unirest.post(String.format("%s/%s", BASE_URL, AUTH_PATH))
                .header("Content-Type",APPLICATION_JSON)
                .header("state-cd", state)
                .header("clientid", clientId)
                .header("client-secret", clientSecret)
                .header("ip-usr", ipAddr)
                .header("appkey", appKeyEncryptedAndCoded)
                .header("txn", txn)
                .body(new JsonNode(authTokenReq.toString()))
                .asJson();

        System.out.println(String.format("AuthToken Request : Status[%s] Response[%s]", authTokenResp.getStatus(), authTokenResp.getBody()));

        if (authTokenResp.getStatus() == 200) {
            JSONObject object = authTokenResp.getBody().getObject();
            if (object.has("auth_token")
                    && object.has("sek")
                    && object.has("status_cd")
                    && Objects.equals(object.getString("status_cd"), "1")) {

                authToken = object.getString("auth_token");
                String sek = object.getString("sek");

                authSEK = aesEncryption.decrypt(sek, aesEncryption.decodeBase64StringTOByte(
                        aesEncryption.encodeBase64String(appKeyInBytes)
                ));
                System.out.println("AuthSEK = "+ aesEncryption.encodeBase64String(authSEK));

                return true;
            }


        }
        return false;
    }

    public boolean otpRequest() throws Exception {
        JSONObject otpRequest = new JSONObject();
        otpRequest.put("action", OTPREQUEST);
        otpRequest.put("appkey", appKeyEncryptedAndCoded);
        otpRequest.put("username", userName);

        HttpResponse<JsonNode> otpResp = Unirest.post(String.format("%s/%s", BASE_URL, AUTH_PATH))
                .header("clientid", clientId)
                .header("state-cd", state)
                .header("username", userName)
                .header("txn", txn)
                .header("appkey", appKeyEncryptedAndCoded)
                .header("client-secret", clientSecret)
                .header("ip-usr", ipAddr)
                .header("Content-Type", APPLICATION_JSON)
                .body(new JsonNode(otpRequest.toString()))
                .asJson();

        System.out.println(String.format("OTP Request : Status[%s] Response[%s]", otpResp.getStatus(), otpResp.getBody()));

        if (otpResp.getStatus() == 200) {
            JSONObject object = otpResp.getBody().getObject();
            return object.has("status_cd") && Objects.equals(object.getString("status_cd"), "1");
        }
        return false;
    }
}
