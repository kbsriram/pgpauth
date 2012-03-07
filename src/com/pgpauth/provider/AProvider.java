package com.pgpauth.provider;

/*
 * This provides some generic OAuth checking for various sites
 * we decide to handle.
 *
 * It handles everything from handling the oauth details, to
 * obtaining profile data and finally verifying it with the
 * certificate information.
 */

import com.pgpauth.common.Utils;
import com.pgpauth.common.CUserID;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.common.D;
import com.pgpauth.servlet.U;

import com.google.appengine.api.taskqueue.TaskOptions;
import com.google.appengine.api.taskqueue.Queue;
import com.google.appengine.api.taskqueue.QueueFactory;

import java.io.Serializable;
import java.util.Properties;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.io.IOException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;
import javax.servlet.http.HttpServletRequest;

public abstract class AProvider
    implements Serializable
{
    public synchronized static void init()
        throws IOException
    {
        BufferedReader br = null;
        try {
            br = new BufferedReader
                (new FileReader("WEB-INF/oauth.properties"));
            Properties p = new Properties();
            p.load(br);

            br.close();
            br = null;

            s_providers = new ArrayList<AProvider>();
            String suffix = Utils.isProduction()?
                ".prod.appkey":".dev.appkey";
            int slen = suffix.length();
            String ssuffix = Utils.isProduction()?
                ".prod.appsecret":".dev.appsecret";

            for (String prop: p.stringPropertyNames()) {
                if (!prop.endsWith(suffix)) {
                    continue;
                }
                String ptype = prop.substring(0, prop.length()-slen);
                Class<? extends AProvider> c =
                    Class.forName
                    ("com.pgpauth.provider.C"+ptype+"Provider")
                    .asSubclass(AProvider.class);
                AProvider provider = c.newInstance();
                provider.setAppKey(p.getProperty(prop));
                provider.setAppSecret(p.getProperty(ptype+ssuffix));
                s_providers.add(provider);
                log(Level.INFO, "Added provider: "+c);
            }
        }
        catch (IllegalAccessException iae) {
            throw new IOException(iae);
        }
        catch (InstantiationException ie) {
            throw new IOException(ie);
        }
        catch (ClassNotFoundException cnfe) {
            throw new IOException(cnfe);
        }
        finally {
            if (br != null) { br.close(); }
        }
    }

    public static AProvider forType(String t)
    {
        for (AProvider provider: s_providers) {
            if (provider.getType().equals(t)) {
                return provider;
            }
        }
        return null;
    }

    // Given a String transform it into a CUserID, or 
    // null if we can't handle this.
    public static CUserID fromString(String s)
    {
        if (Utils.isEmpty(s)) { return null; }

        for (AProvider provider: s_providers) {
            CUserID ret = provider.getID(s);
            if (ret != null) { return ret; }
        }
        return null;
    }

    // This should really have been a runtime-exception by
    // all rights.
    protected static String urlencode(String s)
    {
        try { return URLEncoder.encode(s, "utf-8"); }
        catch (UnsupportedEncodingException uee) {
            throw new RuntimeException(uee);
        }
    }

    protected static void log(Level l, String msg)
    { s_logger.log(l, msg); }

    protected void setAppKey(String s)
    { m_appkey = s; }

    protected void setAppSecret(String s)
    { m_appsecret = s; }

    // Enqueue a task so we can relinquish any OAuth permissions.
    protected void addRevokeTask(AProvider p, TaskOptions options)
    {
        Queue q = QueueFactory.getDefaultQueue();

        q.add
            (options.param(REVOKE_TYPE, p.getType())
             .url("/tasks/revoke"));
    }

    protected abstract CUserID getID(String s);
    public abstract String getType();
    public abstract String getSiteName();
    public abstract String getAuthDomain();
    public abstract String getProfileLinkFor(String pid);
    public abstract String getProfileQueryFor(String pid);
    public abstract String getProfileLinkNameFor(String pid);
    public abstract D getDisclosure(CUserID id, CNonceOp.Type type);
    public abstract String getAuthURL(CNonceOp nonce)
        throws IOException;
    public abstract AProviderInfo getInfoFrom
        (CNonceOp nonce, HttpServletRequest req)
        throws IOException;
    public abstract boolean accepts
        (AProviderInfo info, CUserID uid);
    public abstract void revoke(HttpServletRequest req)
        throws IOException;

    protected String m_appkey = null;
    protected String m_appsecret = null;

    public final static String REVOKE_TYPE = "_revoke_type";
    private static List<AProvider> s_providers;
    private final static Logger s_logger =
        Logger.getLogger(AProvider.class.getName());

}