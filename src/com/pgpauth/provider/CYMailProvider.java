package com.pgpauth.provider;

import com.pgpauth.common.CUserID;
import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.oauth.COAuth1a;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.HashMap;
import java.net.URL;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.json.JSONObject;

import java.util.logging.Logger;
import java.util.logging.Level;

public class CYMailProvider
    extends AProvider
{
    static final long serialVersionUID = 2454721964696841767L;
    @Override
    public String getType()
    { return "YMAIL"; }

    @Override
        public final D getDisclosure(CUserID id, CNonceOp.Type t)
    {
        D ret = D.createNode("div", "class", "info_description");
        StringBuffer sb = new StringBuffer
            ("OpenPGPAuth will ask your permission to let it access your Yahoo! profile information, which contains your Yahoo! <span class='notice'>email address</span>. We match the email address with <tt class='notice'>");
        sb.append(id.getProviderID());
        sb.append
            ("@yahoo.com</tt>, which is what your public key uses.");
        ret.addChild
            (D.wrapText("p", sb.toString()));
        ret.addChild
            (D.wrapText
             ("p",
              "We only fetch your profile data from yahoo, and also discard everything other than the <span class='notice'>email address</span> from it."));

        return ret;
    }

    @Override
    public String getSiteName()
    { return "Yahoo"; }

    @Override
    public String getAuthDomain()
    { return "api.login.yahoo.com"; }

    @Override
    public String getProfileQueryFor(String pid)
    { return pid+"@yahoo.com"; }

    @Override
    public String getProfileLinkFor(String pid)
    { return "mailto:"+pid+"@yahoo.com"; }

    @Override
    public String getProfileLinkNameFor(String pid)
    { return pid+"@yahoo.com"; }

    @Override
    public void revoke(HttpServletRequest req)
        throws IOException
    { throw new IOException("Yahoo cannot revoke credentials"); }

    @Override
    public String getAuthURL(CNonceOp nop)
        throws IOException
    {
        // OAuth 1.0 -- need to first acquire a request token/secret
        COAuth1a.Store store = COAuth1a.getRequestToken
            (new URL
             ("https://api.login.yahoo.com/oauth/v2/get_request_token"),
             "yahooapis.com",
             "https://pgpauth.appspot.com/yahoo/oauth1a",
             m_appkey, m_appsecret, nop);

        return
            "https://api.login.yahoo.com/oauth/v2/request_auth?oauth_token="
            +store.getToken();
    }

    @Override
    public AProviderInfo getInfoFrom(CNonceOp nop, HttpServletRequest req)
        throws IOException
    {
        AProviderInfo ret = COAuth1a.checkErrors(nop, req);
        if (ret != null) { return ret; }

        // Should have good data now. Proceed on to exchanging for
        // an access token.
        COAuth1a.Store store = COAuth1a.exchange
            (new URL("https://api.login.yahoo.com/oauth/v2/get_token"),
             "yahooapis.com",
             m_appkey, m_appsecret, nop, req);

        // Finally, make a request to obtain profile info, which should
        // contain an email address; among other stuff.
        JSONObject resp = COAuth1a.fetchJSON
            (new URL("http://query.yahooapis.com/v1/yql?q="+
                     "select%20%2A%20from%20social.profile%20where%20guid%3Dme"+
                     "&format=json"),
             "yahooapis.com", m_appkey, m_appsecret, store);

        if (!resp.has("query")) {
            return new ErrorInfo("Sorry, no results found in Yahoo profile");
        }
        JSONObject query = resp.getJSONObject("query");
        if (!query.has("results")) {
            return new ErrorInfo("Sorry, no results found in Yahoo profile");
        }
        JSONObject results = query.getJSONObject("results");
        if (!results.has("profile")) {
            return new ErrorInfo("Sorry, no profile data returned from Yahoo");
        }
        JSONObject profile = results.getJSONObject("profile");
        if (!profile.has("emails")) {
            return new ErrorInfo("Sorry, no email data returned from Yahoo");
        }
        JSONObject emails = profile.getJSONObject("emails");
        if (!emails.has("handle")) {
            return new ErrorInfo("Sorry, no email found in Yahoo profile");
        }

        String em = emails.getString("handle");
        String imurl = null;
        /*
        if (profile.has("image") &&
            profile.getJSONObject("image").has("imageUrl")) {
            imurl =
                profile.getJSONObject("image").getString("imageUrl");
        }
        */

        return new Info(em, imurl);
    }

    @Override
    public boolean accepts(AProviderInfo info, CUserID id)
    {
        if (!(info instanceof Info)) { return false; }
        String pem = info.getProviderID();
        String idem = id.getProviderID();

        // NB -- we return the full email address above, for the
        // provider id.
        return
            (pem != null) &&
            (idem != null) &&
            (pem.equalsIgnoreCase(idem+"@yahoo.com"));
    }

    @Override
    protected CUserID getID(String s)
    {
        Matcher m = GPG_EMAIL.matcher(s);
        if (m.matches()) {
            return new CUserID
                (s, m.group(5).toLowerCase(), m.group(1), m.group(3), this);
        }

        if ((m = BARE_EMAIL.matcher(s)).matches()) {
            return new CUserID
                (s, m.group(1).toLowerCase(), m.group(1), null, this);
        }

        return null;
    }

    public final static class Info
        extends AProviderInfo
    {
        private Info(String em, String imurl)
        {
            super(AProviderInfo.State.OK, null, em, null, imurl);
        }
    }

    public final static class ErrorInfo
        extends AProviderInfo
    {
        private ErrorInfo(String msg)
        {
            super(AProviderInfo.State.ERROR, msg, null, null, null);
        }
    }

    private final static Pattern GPG_EMAIL =
        Pattern.compile
        (
         "([^\\(\\)]+)?\\s*" // username, optional
         +"(\\((.*)\\))?\\s*" // comment, optional
         +"<(([a-zA-Z0-9_\\.]+)@(yahoo.com))>",
         Pattern.CASE_INSENSITIVE
         );

    private final static Pattern BARE_EMAIL =
        Pattern.compile
        (
         "([a-zA-Z0-9_\\.]+)@(yahoo.com)",
         Pattern.CASE_INSENSITIVE
         );

    private final static Logger s_logger =
        Logger.getLogger(CYMailProvider.class.getName());

}