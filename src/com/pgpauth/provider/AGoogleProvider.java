package com.pgpauth.provider;

/*
 * Gmail and G+ are close enough that some chunk of
 * the code can be pulled up.
 */

import com.pgpauth.common.CUserID;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.common.D;
import com.pgpauth.oauth.COAuth2;


import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.HashMap;
import java.net.URL;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import com.google.appengine.api.taskqueue.TaskOptions;

import java.util.logging.Logger;
import java.util.logging.Level;

public abstract class AGoogleProvider
    extends AProvider
{
    @Override
    public final String getSiteName()
    { return "Google"; }

    @Override
    public final String getAuthDomain()
    { return "accounts.google.com"; }

    @Override
    public final String getAuthURL(CNonceOp nop)
    {
        // OAuth2, easy-peasy
        StringBuilder sb = new StringBuilder
            ("https://accounts.google.com/o/oauth2/auth?response_type=code");
        sb.append("&approval_prompt=force");
        sb.append("&client_id=");
        sb.append(urlencode(m_appkey));
        sb.append("&redirect_uri=");
        sb.append(urlencode(getRedirectUrl()));
        sb.append("&scope=");
        sb.append
            (urlencode(getScope()));
        sb.append("&state=");
        sb.append(nop.getNonce());
        return sb.toString();
    }

    @Override
    public final AProviderInfo getInfoFrom(CNonceOp nop, HttpServletRequest req)
        throws IOException
    {
        // some boilerplate checks go in here.
        AProviderInfo ret = COAuth2.checkErrors(nop, req);
        if (ret != null) { return ret; }

        // We ought to have a good code now. Build up to exchange
        // for an access token
        Map<String,String> post = new HashMap<String,String>();
        post.put("code", req.getParameter("code"));
        post.put("client_id", m_appkey);
        post.put("client_secret", m_appsecret);
        post.put("redirect_uri", getRedirectUrl());
        post.put("grant_type", "authorization_code");

        JSONObject jdata =
            Utils.fetchJSON
            (new URL
             ("https://accounts.google.com/o/oauth2/token"),
             post, 10*1000);

        String access_token = jdata.optString("access_token", null);
        if (Utils.isEmpty(access_token)) {
            throw new IOException("Failed oauth exchange: "+
                                  jdata.optString("error", "unknown"));
        }

        ret = infoFromToken(access_token);

        // task to revoke our access.
        addRevokeTask
            (this, TaskOptions.Builder
             .withParam("access_token", access_token));
        return ret;
    }

    @Override
    public void revoke(HttpServletRequest req)
        throws IOException
    {
        String rtok = req.getParameter("access_token");
        if (Utils.isEmpty(rtok)) {
            log(Level.WARNING, "Unable to find access_token for revocation");
            return;
        }

        log(Level.INFO, Utils.fetchString
            (new URL("https://accounts.google.com/o/oauth2/revoke?token="+
                     urlencode(rtok)), null, 10*1000));
    }

    private final static String getRedirectUrl()
    {
        return
            Utils.isProduction()?
            "https://pgpauth.appspot.com/google/oauth2":
            "http://localhost:8080/google/oauth2";
    }

    protected abstract String getScope();

    protected abstract AProviderInfo infoFromToken(String tok)
        throws IOException;
}
