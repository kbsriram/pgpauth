package com.pgpauth.servlet;

import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CVerifyCertificate;
import com.pgpauth.common.CNonceOp;

import com.pgpauth.provider.AProvider;

import java.util.List;
import java.net.URL;
import java.net.URLEncoder;
import java.net.MalformedURLException;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServlet;

import java.util.logging.Logger;
import java.util.logging.Level;

// Template class to do any sort of writeable operation on a certificate
// (add, delete)

public abstract class AOpCertificateServlet
    extends HttpServlet
{
    @Override
    protected void doPost
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        // Discover referer, callback url and state, if any.
        URL referer = asURL
            (req.getHeader("Referer"), req, resp, true, "Referer URL");
        if (referer == null) {
            return;
        }
        s_logger.log(Level.INFO, "add-certificate from "+referer);
        URL cburl = asURL
            (req.getParameter("cburl"), req, resp, false, "Callback URL");
        String cbstate = req.getParameter("cbstate");

        if (!validate(referer, cburl, req, resp)) {
            // errors handled here.
            return;
        }

        CVerifyCertificate.Info cert = getCertificate(req, resp);
        if (cert == null) {
            // error handled by subclass.
            return;
        }

        // Create a nonce-op that we'll use to handle authenticated
        // responses.
        CNonceOp nop = new CNonceOp(getOpType(), cert, cburl, cbstate);


        // Generate an appropriate OAuth URL
        String url = cert.getID().getProvider()
            .getAuthURL(nop);

        // Store the nonce-op in memcache so we can fish it out later.
        // Note: don't update content of nop after storing it in
        // memcache, because it won't necessarily be reflected
        // when you fetch it.
        Utils.storeMemCache(Utils.NS.SESSION, nop.getId(), nop, 600*1000);

        // Also store a secure, no-js cookie with this id
        U.addSecureCookie(resp, "o2", nop.getId());

        // Make an area for the certificate info
        D dcert = U.format(cert, false);

        // Let the subclass add buttons and other information.
        String cancel_url;
        if (cburl != null) {
            cancel_url = cburl.toString()+"?status=cancel";
            if (!Utils.isEmpty(cbstate)) {
                cancel_url += "&cbstate="+URLEncoder.encode(cbstate, "utf-8");
            }
        }
        else {
            cancel_url = "/";
        }

        D rest =
            makeContent(cert, referer.getHost(), url, cancel_url);
        D content = D.createNode("div", "class", "main");
        content.addChild(dcert);
        content.addChild(rest);
        D.dumpContent
            (resp.getWriter(), "Verification | OpenPGPAuth", content,
             "/static/js/infotoggle.js");
    }

    private final static URL asURL
        (String s, HttpServletRequest req, HttpServletResponse resp,
         boolean requiredp, String msg)
        throws IOException
    {
        if (Utils.isEmpty(s)) {
            if (requiredp) {
                U.forbid(req, resp, "Missing "+msg);
            }
            return null;
        }

        try {
            URL ret = new URL(s);
            String p = ret.getProtocol();
            if (!"http".equalsIgnoreCase(p) &&
                !"https".equalsIgnoreCase(p)) {
                U.forbid
                    (req, resp,
                     "Only http/https "+msg+" are permitted");
                    return null;
            }
            return ret;
        }
        catch (MalformedURLException mfe) {
            s_logger.log(Level.INFO, "bad "+msg, mfe);
            U.forbid(req, resp, "Invalid "+msg);
            return null;
        }
    }

    private final static boolean validHostname(String s)
    {
        char[] chars = s.toCharArray();
        boolean hasalpha = false;
        for (int i=0; i<chars.length; i++) {
            char c = chars[i];
            if (((c >= 'a') && (c <= 'z')) ||
                ((c >= 'A') && (c <= 'Z'))) {
                hasalpha = true;
            }
            else if (((c >= '0') && (c <= '9')) ||
                     (c == '.') || (c == '-') ||
                     (c == '_') /* not-compliant, but ok */) {
                // ok
            }
            else {
                return false;
            }
        }
        return hasalpha;
    }

    private final static boolean validate
        (URL referer, URL cburl, HttpServletRequest req,
         HttpServletResponse resp)
        throws IOException
    {
        if (cburl != null) {
            // 1) must not be a pure IP address
            // 2) must not itself have query parameters.
            // 3) Hostname must match referer
            if (!Utils.isEmpty(cburl.getQuery())) {
                U.forbid
                    (req, resp,
                     "Callback URLs must not have query parameters");
                return false;
            }

            if (!validHostname(cburl.getHost())) {
                U.forbid
                    (req, resp, "Invalid callback hostname");
                return false;
            }

            if (!referer.getHost().equalsIgnoreCase(cburl.getHost())) {
                U.forbid
                    (req, resp, "Referer does not match callback URL");
                return false;
            }
        }

        // good to go.
        return true;
    }

    protected abstract CVerifyCertificate.Info getCertificate
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException;

    protected abstract CNonceOp.Type getOpType();

    protected abstract D makeContent
        (CVerifyCertificate.Info info,
         String refer_host,
         String ok_url,
         String cancel_url);

    private final static Logger s_logger =
        Logger.getLogger(AOpCertificateServlet.class.getName());
}
