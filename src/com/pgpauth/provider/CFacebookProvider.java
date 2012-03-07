package com.pgpauth.provider;

import com.pgpauth.common.CUserID;
import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.oauth.COAuth2;

import com.google.appengine.api.taskqueue.TaskOptions;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.HashMap;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.json.JSONObject;

import java.util.logging.Logger;
import java.util.logging.Level;

public class CFacebookProvider
    extends AProvider
{
    static final long serialVersionUID = 5206218999811559681L;

    @Override
    protected CUserID getID(String s)
    {
        String pid = null;
        Matcher m = GPG_PROFILE.matcher(s);
        if (m.matches()) {
            return new CUserID
                (s, m.group(5).toLowerCase(), m.group(1), m.group(3), this);
        }

        if ((m = BARE_PROFILE.matcher(s)).matches()) {
            return new CUserID
                (s, m.group(2).toLowerCase(), m.group(2), null, this);
        }

        return null;
    }

    @Override
    public String getType()
    { return "FACEBOOK"; }

    @Override
    public final D getDisclosure(CUserID id, CNonceOp.Type t)
    {
        D ret = D.createNode("div", "class", "info_description");
        StringBuffer sb = new StringBuffer
            ("OpenPGPAuth will ask your permission to access basic information about your Facebook account. It will match your Facebook <span class='notice'>userid</span> or <span class='notice'>username</span> with <tt class='notice'>");
        sb.append(id.getProviderID());
        sb.append
            ("</tt>, which is what your public key uses.");
        ret.addChild
            (D.wrapText("p", sb.toString()));
        if (t == CNonceOp.Type.ADD) {
            ret.addChild
                (D.wrapText
                 ("p",
                  "We only access your Facebook user information, compare your <span class='notice'>userid</span> or <span class='notice'>username</span>, and store your <span class='notice'>name</span> and a link to your <span class='notice'>profile photo</span> so they can be shown when displaying your public key."));
        }
        return ret;
    }

    @Override
    public String getSiteName()
    { return "Facebook"; }

    @Override
    public String getAuthDomain()
    { return ".facebook.com"; }

    @Override
    public String getProfileQueryFor(String pid)
    { return getProfileLinkFor(pid); }

    @Override
    public String getProfileLinkFor(String pid)
    { return "https://www.facebook.com/"+pid; }

    @Override
    public String getProfileLinkNameFor(String pid)
    { return "Facebook page"; }

    @Override
    public String getAuthURL(CNonceOp nop)
    {
        StringBuilder sb = new StringBuilder
            ("https://www.facebook.com/dialog/oauth?auth_type=reauthenticate");
        sb.append("&client_id=");
        sb.append(urlencode(m_appkey));
        sb.append("&redirect_uri=");
        sb.append(urlencode(getRedirectUrl()));
        sb.append("&state=");
        sb.append(nop.getNonce());
        return sb.toString();
    }

    @Override
    public AProviderInfo getInfoFrom
        (CNonceOp nop, HttpServletRequest req)
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

        Map<String,String> vals = Utils.fetchForm
            (new URL
             ("https://graph.facebook.com/oauth/access_token"),
             post, 10*1000);

        String access_token = vals.get("access_token");
        if (Utils.isEmpty(access_token)) {
            throw new IOException("Failed oauth exchange");
        }

        // Acquire profile info.
        JSONObject jdata = Utils.fetchJSON
            (new URL
             ("https://graph.facebook.com/me?access_token="+
              urlencode(access_token)), null, 10*1000);

        String pid = jdata.optString("id", null);
        if (pid == null) {
            throw new IOException("Missing id from profile");
        }
        // This is optional, but may be used to match the
        // pgp name if it exists.
        String pusrname = jdata.optString("username", null);
        String pdn = jdata.optString("name", null);

        // Finally, enqueue a task to return the OAuth permissions.
        addRevokeTask
            (this, TaskOptions.Builder
             .withParam("access_token", access_token));

        return new Info
            (pid, pusrname, pdn,
             "https://graph.facebook.com/"+pid+"/picture?type=normal");
    }

    @Override
    public boolean accepts(AProviderInfo info, CUserID id)
    {
        if (!(info instanceof Info)) { return false; }

        Info finfo = (Info) info;

        String pid = info.getProviderID();
        String idem = id.getProviderID();
        String pun = finfo.getFbUsername();

        if (Utils.isEmpty(idem)) { return false; }
        if (idem.equalsIgnoreCase(pid)) { return true; }
        return idem.equalsIgnoreCase(pun);
    }

    @Override
    public void revoke(HttpServletRequest req)
        throws IOException
    {
        String atok = req.getParameter("access_token");
        if (Utils.isEmpty(atok)) {
            log(Level.WARNING, "Unable to find access_token during revocation");
            return;
        }

        // Send a delete request to this URL.
        Map<String,String> params = new HashMap<String,String>();
        params.put("method", "delete");
        params.put("access_token", atok);

        log(Level.INFO, "deleting: "+
            Utils.fetchString
            (new URL
             ("https://graph.facebook.com/me/permissions"),
             params, 10*1000));
    }

    private final static String getRedirectUrl()
    {
        return
            Utils.isProduction()?
            "https://pgpauth.appspot.com/facebook/oauth2":
            "http://localhost:8080/facebook/oauth2";
    }


    public final static class Info
        extends AProviderInfo
    {
        private Info(String pid, String fun, String pdn, String ppic)
        {
            super(AProviderInfo.State.OK, null, pid, pdn, ppic);
            m_fun = fun;
        }
        private String getFbUsername()
        { return m_fun; }
        private final String m_fun;
    }



    private final static Pattern GPG_PROFILE =
        Pattern.compile
        (
         "([^\\(\\)]+)?\\s*" // username, optional
         +"(\\((.*)\\))?\\s*" // comment, optional
         +"<https?://(www\\.)?facebook\\.com/([a-zA-Z0-9_\\.]+)>",
         Pattern.CASE_INSENSITIVE
         );

    private final static Pattern BARE_PROFILE =
        Pattern.compile
        (
         "https?://(www\\.)?facebook\\.com/([a-zA-Z0-9\\.]+)",
         Pattern.CASE_INSENSITIVE
         );

}