package net.smartgst.auth;

import org.aeonbits.owner.Config;

/**
 * Created by gowthaman on 26/5/17.
 */
@Config.Sources({
        "file:~/.gst_credential.config",
        "file:~/.config/gst_credential.config",
        "file:/etc/gst_credential.config"
})
public interface GSTCredential extends Config {

    @Key("cred.client_id")
    String clientId();

    @Key("cred.client_secret")
    String clientSecret();

}
