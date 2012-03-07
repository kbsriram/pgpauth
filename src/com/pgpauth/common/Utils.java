package com.pgpauth.common;

// Kitchen-sink

import com.google.appengine.api.memcache.MemcacheService;
import com.google.appengine.api.memcache.MemcacheServiceFactory;
import com.google.appengine.api.memcache.Expiration;
import com.google.appengine.api.utils.SystemProperty;

import org.json.JSONObject;
import org.json.JSONException;

import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.Random;
import java.util.Map;
import java.util.HashMap;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.BufferedReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.net.URLDecoder;

public class Utils
{
    public final static boolean isProduction()
    {
        return SystemProperty.environment.value() ==
            SystemProperty.Environment.Value.Production;
    }

    public final static <T> T notNull(T t)
    {
        if (t == null) {
            throw new AssertionError("unexpected null value");
        }
        return t;
    }

    public final static boolean isEmpty(String s)
    { return ((s == null) || (s.length() == 0)); }

    public final static void storeMemCache
        (NS ns, String key, Object val, int ts)
    {
        key = ns+"/"+key;
        s_logger.log(Level.INFO, "storing "+key+" for: "+ts+"msec");
        s_memcache.put(key, val, Expiration.byDeltaMillis(ts));
    }

    // Despite the appearance of SHA, this is not intended to
    // be a secure random number.
    public final static String makeNonce()
    {
        byte[] buf = new byte[12];
        synchronized (s_random) {
            s_random.nextBytes(buf);
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return byte2str(buf);
        }
        catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException(nse);
        }
    }

    public final static String byte2str(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
            int cur = (b & 0xff);
            if (cur <= 0xf) {
                sb.append("0");
            }
            sb.append(Integer.toHexString(cur));
        }
        return sb.toString();
    }

    public final static Object removeMemCache(NS ns, String key)
    {
        Object ret = fetchMemCache(ns, key);
        if (ret != null) {
            key = ns+"/"+key;
            s_logger.log(Level.INFO, "Remove-from-memcache: "+key);
            s_memcache.delete(key);
        }
        return ret;
    }

    public final static Object fetchMemCache(NS ns, String key)
    {
        key = ns+"/"+key;
        s_logger.log(Level.INFO, "Find: "+key);
        return s_memcache.get(key);
    }


    public final static JSONObject fetchJSON(URL url)
        throws IOException
    { return fetchJSON(url, null); }

    public final static JSONObject fetchJSON(URL url, Map<String,String> post)
        throws IOException
    { return fetchJSON(url, post, -1); }

    public final static JSONObject fetchJSON
        (URL url, Map<String,String> post, int timeout_msec)
        throws IOException
    {
        try {
            return new JSONObject(fetchString(url, post, timeout_msec));
        }
        catch (JSONException jse) {
            throw new IOException(jse);
        }
    }

    public final static Map<String,String> fetchForm
        (URL url, Map<String,String> post, int timeout_msec)
        throws IOException
    {
        String s = fetchString(url, post, timeout_msec);
        Map<String,String> ret = new HashMap<String,String>();
        if (isEmpty(s)) { return ret; }
        String fields[] = s.split("&");
        for (int i=0; i<fields.length; i++) {
            String kv[] = fields[i].split("=");
            if (kv.length == 1) {
                ret.put(kv[0], "");
            }
            else if (kv.length == 2) {
                ret.put(kv[0], URLDecoder.decode(kv[1], "utf-8"));
            }
            else {
                throw new IOException("bad form data: '"+s+"'");
            }
        }
        return ret;
    }

    public final static String fetchString(URL url)
        throws IOException
    { return fetchString(url, null); }

    public final static String fetchString(URL url, Map<String,String> post)
        throws IOException
    { return fetchString(url, post, -1); }

    public final static String fetchString
        (URL url, Map<String,String> post, int timeout_msec)
        throws IOException
    {
        if (post == null) {
            s_logger.log(Level.INFO, url.toString());
        }
        else {
            s_logger.log(Level.INFO, url.toString()+": "+post);
        }

        URLConnection con = url.openConnection();
        if (timeout_msec > 0) {
            con.setReadTimeout(timeout_msec);
        }
        if (post != null) {
            con.setDoOutput(true);
            OutputStreamWriter wr =
                new OutputStreamWriter(con.getOutputStream());
            int len = post.size();
            for (String k: post.keySet()) {
                wr.write(k);
                wr.write("=");
                wr.write(URLEncoder.encode(post.get(k), "utf-8"));
                if (--len > 0) {
                    wr.write("&");
                }
            }
            wr.flush();
        }

        return fetchStringFrom(con.getInputStream());
    }

    public final static String fetchStringFrom(InputStream inp)
        throws IOException
    {
        BufferedReader br =
            new BufferedReader
            (new InputStreamReader
             (inp));

        try {
            String line;
            boolean first = true;
            StringBuilder ret = new StringBuilder();
            while ((line = br.readLine()) != null) {
                if (first) { first = false; }
                else { ret.append("\n"); }
                ret.append(line);
            }
            s_logger.log(Level.INFO, ret.toString());
            return ret.toString();
        }
        finally {
            try { br.close(); }
            catch (Throwable th) {}
        }                
    }

    public enum NS {
        CERT, SESSION
    };


    private final static MemcacheService s_memcache =
        MemcacheServiceFactory.getMemcacheService();
    private final static Logger s_logger =
        Logger.getLogger(Utils.class.getName());

    private final static Random s_random = new Random();
}
