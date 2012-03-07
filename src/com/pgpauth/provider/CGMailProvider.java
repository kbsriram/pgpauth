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

public class CGMailProvider
    extends AGoogleProvider
{
    static final long serialVersionUID = -514072636870740428L;

    @Override
    public String getType()
    { return "GMAIL"; }

    @Override
    public final D getDisclosure(CUserID id, CNonceOp.Type t)
    {
        D ret = D.createNode("div", "class", "info_description");
        StringBuffer sb = new StringBuffer
            ("OpenPGPAuth will ask your permission to let it view your Gmail <span class='notice'>email address</span>. It will match this email address with <tt class='notice'>");
        sb.append(id.getProviderID());
        sb.append
            ("@gmail.com</tt>, which is what your public key uses.");
        ret.addChild
            (D.wrapText("p", sb.toString()));
        return ret;
    }

    @Override
    public String getProfileQueryFor(String pid)
    { return pid+"@gmail.com"; }

    @Override
    public String getProfileLinkFor(String pid)
    { return "mailto:"+pid+"@gmail.com"; }

    @Override
    public String getProfileLinkNameFor(String pid)
    { return pid+"@gmail.com"; }

    @Override
    protected String getScope()
    { return "https://www.googleapis.com/auth/userinfo.email"; }

    @Override
    protected AProviderInfo infoFromToken(String access)
        throws IOException
    {
        // And get hold of profile info.
        JSONObject jdata = Utils.fetchJSON
            (new URL
             ("https://www.googleapis.com/oauth2/v1/userinfo?access_token="+
              urlencode(access)), null, 10*1000);

        String pem = jdata.optString("email", null);
        if (Utils.isEmpty(pem)) {
            throw new IOException("Missing email data from provider!");
        }

        return new Info(pem);
    }

    @Override
    public boolean accepts(AProviderInfo info, CUserID id)
    {
        if (!(info instanceof Info)) { return false; }

        Info gminfo = (Info) info;

        String pem = info.getProviderID();
        String idem = id.getProviderID();

        // NB -- we return the full email address above, for the
        // provider id.

        return
            (pem != null) &&
            (idem != null) &&
            (pem.equalsIgnoreCase(idem+"@gmail.com"));
    }

    @Override
    protected CUserID getID(String s)
    {
        String pid = null;
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
        private Info(String em)
        {
            super(AProviderInfo.State.OK, null, em, null, null);
        }
    }

    private final static Pattern GPG_EMAIL =
        Pattern.compile
        (
         "([^\\(\\)]+)?\\s*" // username, optional
         +"(\\((.*)\\))?\\s*" // comment, optional
         +"<(([a-zA-Z0-9\\.]+)@(gmail.com))>",
         Pattern.CASE_INSENSITIVE
         );

    private final static Pattern BARE_EMAIL =
        Pattern.compile
        (
         "([a-zA-Z0-9\\.]+)@(gmail.com)",
         Pattern.CASE_INSENSITIVE
         );

}