package com.pgpauth.oauth;

// Grab bag for OAuth 1.0 utilities.

import com.pgpauth.provider.AProviderInfo;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CNonceOp;

import org.json.JSONObject;
import org.json.JSONException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;

import java.util.Map;
import java.util.TreeMap;
import java.util.HashMap;
import java.io.IOException;
import java.io.Serializable;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;
import java.util.logging.Level;

public class COAuth1a
{
    public final static Store getRequestToken
        (URL target, String realm, String cburl, String appkey,
         String appsec, CNonceOp nop)
        throws IOException
    {
        StringBuilder sb = new StringBuilder("POST&");
        sb.append(pencode(url2base(target)));
        sb.append("&");

        TreeMap<String,String> params = new TreeMap<String,String>();
        addParam(params, "oauth_signature_method", "HMAC-SHA1");
        addParam(params, "oauth_timestamp",
                 ""+(System.currentTimeMillis()/1000));
        addParam(params, "oauth_nonce", Utils.makeNonce());
        addParam(params, "oauth_consumer_key", appkey);
        addParam(params, "oauth_callback", cburl);
        addParam(params, "oauth_version", "1.0");

        sb.append(pencode(join(params)));
        String osig = hmac_sha1(appsec, "", sb.toString());

        HttpURLConnection con = (HttpURLConnection) target.openConnection();
        con.setReadTimeout(10*1000);
        con.setRequestMethod("POST");
        authConnection(con, realm, osig, params);

        Map<String,String> resp = fetchForm(con.getInputStream());
        String token = resp.get("oauth_token");
        String token_secret = resp.get("oauth_token_secret");
        if (Utils.isEmpty(token) || Utils.isEmpty(token_secret)) {
            throw new IOException("missing token from oauth");
        }
        Store ret = new Store(token, token_secret);
        nop.setExtra(ret);
        return ret;
    }

    static AProviderInfo checkReferer
        (CNonceOp nop, HttpServletRequest req)
    {
        // This check doesn't work on the dev unfortunately, as
        // the dev server doesn't run ssl.
        if (!Utils.isProduction()) { return null; }

        // Verify we are being redirected from an approved domain.
        String refer = req.getHeader("Referer");

        if (Utils.isEmpty(refer)) {
            return new ErrorInfo
                ("Sorry, this browser isn't sending enough information to know whether it is being redirected from the correct site");
        }

        s_logger.log(Level.INFO, "redirect from: '"+refer+"'");
        refer = refer.toLowerCase();
        URL rurl;
        try { rurl = new URL(refer); }
        catch (MalformedURLException mue) {
            return new ErrorInfo
                ("Sorry, this browser claims to come from an site that doesn't have a proper URL");
        }

        if (!rurl.getHost().endsWith
            (nop.getInfo().getID().getProvider().getAuthDomain())) {
            return new ErrorInfo
                ("Sorry, this browser is coming from an unexpected site after authorization");
        }

        return null;
    }

    public static AProviderInfo checkErrors
        (CNonceOp nop, HttpServletRequest req)
    {
        AProviderInfo ret = checkReferer(nop, req);
        if (ret != null) { return ret; }

        // Check that we got back our oauth parameters.
        String tok = req.getParameter("oauth_token");
        String ver = req.getParameter("oauth_verifier");
        if (Utils.isEmpty(tok) || Utils.isEmpty(ver)) {
            return new ErrorInfo("sorry, missing oauth tokens");
        }

        // Now ensure that we've got a good state, and that the oauth_token
        // we get back matches what we sent.
        Object tmp = nop.getExtra();
        if (tmp == null) {
            return new ErrorInfo("sorry, missing state");
        }
        if (!(tmp instanceof Store)) {
            return new ErrorInfo("sorry, invalid state");
        }
        Store s = (Store) tmp;
        if (!s.getToken().equals(tok)) {
            s_logger.log(Level.INFO, "mismatch: "+s.getToken()+","+tok);
            return new ErrorInfo
                ("sorry, session information is invalid");
        }

        return null;
    }

    public static Store exchange
        (URL target, String realm, String appkey, String appsec, CNonceOp nop,
         HttpServletRequest req)
        throws IOException
    {
        Store store = (Store)(nop.getExtra());

        StringBuilder sb = new StringBuilder("POST&");
        sb.append(pencode(url2base(target)));
        sb.append("&");

        TreeMap<String,String> params = new TreeMap<String,String>();
        addParam(params, "oauth_signature_method", "HMAC-SHA1");
        addParam(params, "oauth_timestamp",
                 ""+(System.currentTimeMillis()/1000));
        addParam(params, "oauth_consumer_key", appkey);
        addParam(params, "oauth_nonce", Utils.makeNonce());
        addParam(params, "oauth_token", store.getToken());
        addParam(params, "oauth_verifier", req.getParameter("oauth_verifier"));

        sb.append(pencode(join(params)));
        String osig = hmac_sha1(appsec, store.getSecret(), sb.toString());
        s_logger.log(Level.INFO, "POST: "+target);
        HttpURLConnection con = (HttpURLConnection) target.openConnection();
        con.setReadTimeout(10*1000);
        con.setRequestMethod("POST");
        authConnection(con, realm, osig, params);

        Map<String,String> resp = fetchForm(con.getInputStream());
        String token = resp.get("oauth_token");
        String token_secret = resp.get("oauth_token_secret");
        if (Utils.isEmpty(token) || Utils.isEmpty(token_secret)) {
            throw new IOException("missing token from oauth");
        }
        return new Store(token, token_secret);
    }

    public static JSONObject fetchJSON
        (URL target, String realm, String appkey, String appsec, Store store)
        throws IOException
    {
        StringBuilder sb = new StringBuilder("GET&");
        sb.append(pencode(url2base(target)));
        sb.append("&");

        TreeMap<String,String> params = new TreeMap<String,String>();
        String qp = target.getQuery();
        if (!Utils.isEmpty(qp)) {
            String qparams[] = qp.split("&");
            for (int i=0; i<qparams.length; i++) {
                String kv[] = qparams[i].split("=");
                if (kv.length != 2) {
                    throw new IOException("sorry -- odd param: "+qparams[i]);
                }
                // already url-encoded.
                params.put(kv[0], kv[1]);
            }
        }

        addParam(params, "oauth_signature_method", "HMAC-SHA1");
        addParam(params, "oauth_timestamp",
                 ""+(System.currentTimeMillis()/1000));
        addParam(params, "oauth_consumer_key", appkey);
        addParam(params, "oauth_version", "1.0");
        addParam(params, "oauth_nonce", Utils.makeNonce());
        addParam(params, "oauth_token", store.getToken());

        sb.append(pencode(join(params)));

        String osig = hmac_sha1(appsec, store.getSecret(), sb.toString());
        s_logger.log(Level.INFO, "GET: "+target);
        HttpURLConnection con = (HttpURLConnection) target.openConnection();
        con.setReadTimeout(10*1000);
        authConnection(con, realm, osig, params);

        try {
            return new JSONObject(Utils.fetchStringFrom(con.getInputStream()));
        }
        catch (JSONException jse) {
            throw new IOException(jse);
        }
    }

    private final static Map<String,String> fetchForm(InputStream in)
        throws IOException
    {
        BufferedReader br = null;
        Map<String,String> ret = new HashMap<String,String>();

        try {
            br =
                new BufferedReader
                (new InputStreamReader(in));

            String line = br.readLine();
            s_logger.log(Level.INFO, "first-line: '"+line+"'");

            boolean bad = false;
            String tmp;
            while ((tmp = br.readLine()) != null) {
                s_logger.log(Level.INFO, "response: '"+tmp+"'");
                bad = true;
            }
            if (bad) {
                throw new IOException("invalid response");
            }
            String fields[] = line.split("&");
            for (int i=0; i<fields.length; i++) {
                String kv[] = fields[i].split("=");
                if (kv.length != 2) {
                    throw new IOException("invalid response: '"+line+"'");
                }
                ret.put(urldecode(kv[0]), urldecode(kv[1]));
            }
            
            return ret;
        }
        finally {
            if (br != null) { br.close(); }
        }
    }
    private final static void authConnection
        (HttpURLConnection con, String realm, String osig,
         TreeMap<String,String>params)
        throws IOException
    {

        StringBuilder authstring = new StringBuilder
            ("OAuth realm=\"yahooapis.com\",");
        authstring.append("oauth_signature=\"");
        authstring.append(pencode(osig));
        authstring.append("\"");
        for (String param: params.keySet()) {
            if (!param.startsWith("oauth_")) { continue; }
            authstring.append(",");
            authstring.append(param);
            authstring.append("=\"");
            authstring.append(params.get(param));
            authstring.append("\"");
        }
        con.setRequestProperty("Authorization", authstring.toString());
    }

    private final static void addParam
        (TreeMap<String,String> params, String k, String v)
    { params.put(pencode(k), pencode(v)); }

    private final static String urldecode(String in)
        throws IOException
    { return URLDecoder.decode(in, "utf-8"); }

    private final static String pencode(String in)
    {
        StringBuilder sb = new StringBuilder();
        char[] chars = in.toCharArray();
        for (int i=0; i<chars.length; i++) {
            char c = chars[i];
            // don't encode these.
            if (((c >= 'A') && (c <= 'Z')) ||
                ((c >= 'a') && (c <= 'z')) ||
                ((c >= '0') && (c <= '9')) ||
                (c == '-') || (c == '.') || (c == '_') || (c == '~')) {
                sb.append(c);
            }
            else {
                sb.append("%");
                if (c < 0x10) { sb.append("0"); }
                sb.append(Integer.toHexString(c).toUpperCase());
            }
        }
        return sb.toString();
    }

    private static String join(TreeMap<String,String> params)
    {
        StringBuilder ret = new StringBuilder();
        boolean first = true;
        for (String skey: params.keySet()) {
            if (first) { first = false; }
            else { ret.append("&"); }
            ret.append(skey);
            ret.append("=");
            ret.append(params.get(skey));
        }
        return ret.toString();
    }

    private static String hmac_sha1(String secret, String token, String b)
        throws IOException
    {
        StringBuilder key = new StringBuilder(pencode(secret));
        key.append("&");
        key.append(pencode(token));

        Mac m;
        try {
            m = Mac.getInstance("HmacSHA1");
            SecretKeySpec skey = new SecretKeySpec
                (key.toString().getBytes("utf-8"), "HmacSHA1");
            m.init(skey);
        }
        catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
        return
            DatatypeConverter.printBase64Binary
            (m.doFinal(b.getBytes("utf-8")));
    }

    private static String url2base(URL target)
    {
        StringBuilder ret = new StringBuilder(target.getProtocol());
        ret.append("://");
        ret.append(target.getHost().toLowerCase());
        int port = target.getPort();
        if (port != -1) {
            if (("http".equals(target.getProtocol()) &&
                 (port != 80)) ||
                ("https".equals(target.getProtocol()) &&
                 (port != 443))) {
                ret.append(":"+target.getPort());
            }
        }

        ret.append(target.getPath());
        return ret.toString();
    }

    public final static class Store
        implements Serializable
    {
        static final long serialVersionUID = 9218832249347211199L;
        private Store(String tok, String sec)
        {
            m_tok = tok;
            m_sec = sec;
        }
        public String getToken()
        { return m_tok; }
        public String getSecret()
        { return m_sec; }
        private final String m_tok;
        private final String m_sec;
    }

    public final static class ErrorInfo
        extends AProviderInfo
    {
        private ErrorInfo(String msg)
        {
            super(AProviderInfo.State.ERROR, msg, null, null, null);
        }
    }

    private final static Logger s_logger =
        Logger.getLogger(COAuth1a.class.getName());
}
