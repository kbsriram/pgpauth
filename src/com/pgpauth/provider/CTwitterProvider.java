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

public class CTwitterProvider
    extends AProvider
{
    static final long serialVersionUID = 1031357531724550020L;
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
    { return "TWITTER"; }

    @Override
    public void revoke(HttpServletRequest req)
        throws IOException
    {
        throw new IOException("Cannot revoke OAuth tokens for twitter");
    }


    @Override
    public final D getDisclosure(CUserID id, CNonceOp.Type t)
    {
        D ret = D.createNode("div", "class", "info_description");
        StringBuffer sb = new StringBuffer
            ("OpenPGPAuth will ask your permission to let it read your tweets and see who you follow. This is more than what we want, but it is the smallest set of permissions Twitter lets us request in order to see your Twitter <span class='notice'>screen name</span>. We compare your screen name with <tt class='notice'>");
        sb.append(id.getProviderID());
        sb.append
            ("</tt>, which is what your public key uses.");
        ret.addChild
            (D.wrapText("p", sb.toString()));
        if (t == CNonceOp.Type.ADD) {
            ret.addChild
                (D.wrapText
                 ("p",
                  "We read your Twitter user information once, match your <span class='notice'>screen name</span>, and store your Twitter <span class='notice'>name</span> and a link to your <span class='notice'>profile photo</span> so they can be shown when displaying your public key."));
        }
        return ret;
    }

    @Override
    public String getSiteName()
    { return "Twitter"; }

    @Override
    public String getAuthDomain()
    { return "api.twitter.com"; }

    @Override
    public String getProfileQueryFor(String pid)
    { return getProfileLinkFor(pid); }

    @Override
    public String getProfileLinkFor(String pid)
    { return "https://twitter.com/"+pid; }

    @Override
    public String getProfileLinkNameFor(String pid)
    { return "Twitter profile"; }

    @Override
    public String getAuthURL(CNonceOp nop)
        throws IOException
    {
        // OAuth 1.0 -- need to first acquire a request token/secret
        COAuth1a.Store store = COAuth1a.getRequestToken
            (new URL
             ("https://api.twitter.com/oauth/request_token"),
             "https://api.twitter.com",
             Utils.isProduction()?
             "https://pgpauth.appspot.com/twitter/oauth1a":
             "http://localhost:8080/twitter/oauth1a",
             m_appkey, m_appsecret, nop);

        return
            "https://api.twitter.com/oauth/authenticate?force_login=true"+
            "&oauth_token="+urlencode(store.getToken());
    }

    @Override
    public AProviderInfo getInfoFrom
        (CNonceOp nop, HttpServletRequest req)
        throws IOException
    {
        // some boilerplate checks go in here.
        AProviderInfo ret = COAuth1a.checkErrors(nop, req);
        if (ret != null) { return ret; }

        // Should have good data now. Proceed on to exchanging for
        // an access token.
        COAuth1a.Store store = COAuth1a.exchange
            (new URL("https://api.twitter.com/oauth/access_token"),
             "https://api.twitter.com",
             m_appkey, m_appsecret, nop, req);

        // Finally, make a request to obtain profile info, which should
        // contain an email address; among other stuff.
        JSONObject jdata = COAuth1a.fetchJSON
            (new URL
             ("https://api.twitter.com/1/account/verify_credentials.json?skip_status=t"),
             "https://api.twitter.com",
             m_appkey, m_appsecret, store);

        String pid = jdata.optString("id_str", null);
        if (pid == null) {
            throw new IOException("Missing id from profile");
        }
        // This is optional, but may be used to match the
        // pgp name if it exists.
        String pusrname = jdata.optString("screen_name", null);
        String pdn = jdata.optString("name", null);
        String ppic = jdata.optString("profile_image_url_https", null);

        // hack to get bigger twitter img without additional
        // api calls.
        if ((ppic != null) && (ppic.endsWith("_normal.jpg"))) {
            ppic = ppic.substring(0, ppic.length()-10)+"bigger.jpg";
        }

        return new Info
            (pid, pusrname, pdn, ppic);
    }

    @Override
    public boolean accepts(AProviderInfo info, CUserID id)
    {
        if (!(info instanceof Info)) { return false; }

        Info finfo = (Info) info;

        String pid = info.getProviderID();
        String idem = id.getProviderID();
        String tsn = finfo.getTwitterScreenName();

        if (Utils.isEmpty(idem)) { return false; }
        if (idem.equalsIgnoreCase(pid)) { return true; }
        return idem.equalsIgnoreCase(tsn);
    }

    public final static class Info
        extends AProviderInfo
    {
        private Info(String pid, String tsn, String pdn, String ppic)
        {
            super(AProviderInfo.State.OK, null, pid, pdn, ppic);
            m_tsn = tsn;
        }
        private String getTwitterScreenName()
        { return m_tsn; }
        private final String m_tsn;
    }

    private final static Pattern GPG_PROFILE =
        Pattern.compile
        (
         "([^\\(\\)]+)?\\s*" // username, optional
         +"(\\((.*)\\))?\\s*" // comment, optional
         +"<https?://(www\\.)?twitter\\.com/([a-zA-Z0-9_\\.]+)>",
         Pattern.CASE_INSENSITIVE
         );

    private final static Pattern BARE_PROFILE =
        Pattern.compile
        (
         "https?://(www\\.)?twitter\\.com/([a-zA-Z0-9\\.]+)",
         Pattern.CASE_INSENSITIVE
         );

}