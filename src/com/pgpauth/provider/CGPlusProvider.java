package com.pgpauth.provider;

import com.pgpauth.common.CUserID;
import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.oauth.COAuth2;

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

public class CGPlusProvider
    extends AGoogleProvider
{
    static final long serialVersionUID = -8747111742510196797L;
    @Override
    public String getType()
    { return "GPLUS"; }

    @Override
    public final D getDisclosure(CUserID id, CNonceOp.Type t)
    {
        D ret = D.createNode("div", "class", "info_description");
        StringBuffer sb = new StringBuffer
            ("OpenPGPAuth will ask your permission to let it access some basic information about your Google+ account. It will match your Google <span class='notice'>userid</span> with <tt class='notice'>");
        sb.append(id.getProviderID());
        sb.append
            ("</tt>, which is what your public key uses.");
        ret.addChild
            (D.wrapText("p", sb.toString()));
        if (t == CNonceOp.Type.ADD) {
            ret.addChild
                (D.wrapText
                 ("p",
                  "We read just the <span class='notice'>userid</span> from your user information, and store your <span class='notice'>name</span> and a link to any <span class='notice'>profile photo</span> so we can show it when displaying your public key."));
        }
        return ret;
    }


    @Override
    public String getProfileQueryFor(String pid)
    { return getProfileLinkFor(pid); }

    @Override
    public String getProfileLinkFor(String pid)
    { return "https://plus.google.com/"+pid; }

    @Override
    public String getProfileLinkNameFor(String pid)
    { return "Google+ page"; }

    @Override
    protected String getScope()
    { return "https://www.googleapis.com/auth/userinfo.profile"; }

    @Override
    protected AProviderInfo infoFromToken(String access)
        throws IOException
    {
        // And get hold of profile info.
        JSONObject jdata = Utils.fetchJSON
            (new URL
             ("https://www.googleapis.com/oauth2/v1/userinfo?access_token="+
              urlencode(access)), null, 10*1000);

        String pid = jdata.optString("id", null);
        if (pid == null) {
            throw new IOException("Missing id from google!");
        }
        String pdn = jdata.optString("name", null);
        String ppic = jdata.optString("picture", null);
        return new Info(pid, pdn, ppic);
    }

    @Override
    public boolean accepts(AProviderInfo info, CUserID id)
    {
        if (!(info instanceof Info)) { return false; }

        String pem = info.getProviderID();
        String idem = id.getProviderID();

        log(Level.INFO, "Compare: "+pem+","+idem);

        return
            (pem != null) &&
            (idem != null) &&
            (pem.equalsIgnoreCase(idem));
    }

    @Override
    protected CUserID getID(String s)
    {
        String pid = null;
        Matcher m = GPG_PROFILE.matcher(s);
        if (m.matches()) {
            return new CUserID
                (s, m.group(4).toLowerCase(), m.group(1), m.group(3), this);
        }

        if ((m = BARE_PROFILE.matcher(s)).matches()) {
            return new CUserID
                (s, m.group(1).toLowerCase(), m.group(1), null, this);
        }

        return null;
    }

    public final static class Info
        extends AProviderInfo
    {
        private Info(String pid, String pdn, String ppic)
        {
            super(AProviderInfo.State.OK, null, pid, pdn, ppic);
        }
    }

    private final static Pattern GPG_PROFILE =
        Pattern.compile
        (
         "([^\\(\\)]+)?\\s*" // username, optional
         +"(\\((.*)\\))?\\s*" // comment, optional
         +"<https?://plus\\.google\\.com/([a-zA-Z0-9\\.]+)>",
         Pattern.CASE_INSENSITIVE
         );

    private final static Pattern BARE_PROFILE =
        Pattern.compile
        (
         "https?://plus\\.google\\.com/([a-zA-Z0-9\\.]+)",
         Pattern.CASE_INSENSITIVE
         );

}