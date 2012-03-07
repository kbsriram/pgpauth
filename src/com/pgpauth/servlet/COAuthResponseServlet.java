package com.pgpauth.servlet;

// This common servlet is used to handle oauth redirects
// originating from the provider.

import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CVerifyCertificate;
import com.pgpauth.common.CUserID;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.provider.AProviderInfo;
import com.pgpauth.provider.AProvider;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;
import java.util.logging.Logger;
import java.util.logging.Level;

@SuppressWarnings("serial")
public class COAuthResponseServlet
    extends HttpServlet
{
    @Override
    protected void service
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        // First determine our provider.
        String spath = req.getServletPath();
        s_logger.log(Level.INFO, "found on path: "+spath);

        String nonce_id = U.removeCookie(req, resp, "o2", spath);
        s_logger.log(Level.INFO, "nonce id: "+nonce_id);

        if (nonce_id == null) {
            U.forbid(req, resp, "Sorry, missing session state");
            return;
        }

        // Check we have a corresponding nonce in memcache.
        CNonceOp nop = (CNonceOp)
            Utils.fetchMemCache(Utils.NS.SESSION, nonce_id);

        if (nop == null) {
            U.forbid(req, resp, "Sorry, unable to find any match in session");
            return;
        }

        CVerifyCertificate.Info cert = nop.getInfo();

        AProviderInfo pinfo = cert.getID().getProvider().getInfoFrom(nop, req);

        switch (pinfo.getState()) {
        case OK:
            handleOK(nop, pinfo, cert, req, resp);
            break;
        case CANCEL:
            handleCancel(nop, req, resp);
            break;
        case ERROR:
            handleError(nop, pinfo, req, resp);
            break;
        default:
            throw new RuntimeException("not done");
        }
    }

    private final static void handleCancel
        (CNonceOp nop, HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        // If the nop has a callback, go there -- otherwise, redirect
        // to the main.
        String redirect = "/";
        URL cb = nop.getCbURL();
        if (cb != null) {
            redirect = cb.toString()+"?status=cancel";
            String st = nop.getCbState();
            if (!Utils.isEmpty(st)) {
                redirect += "&state="+URLEncoder.encode(st, "utf-8");
            }
        }
        resp.sendRedirect(redirect);
    }

    private final static void handleError
        (CNonceOp nop, AProviderInfo pinfo,
         HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        s_logger.log(Level.INFO, "Unexpected error: "+pinfo.getMessage());
        U.forbid(req, resp, pinfo.getMessage());
    }

    private final static void handleOK
        (CNonceOp nop, AProviderInfo pinfo, CVerifyCertificate.Info cert,
         HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        // We got back the provider info, now see if the code thinks
        // there is really a match.
        CUserID id = cert.getID();
        if (!id.getProvider().accepts(pinfo, id)) {
            U.forbid
                (req, resp, "Sorry -- information in your PGP key: "+
                 id.getOriginal()+" doesn't match your id: "+
                 pinfo.getProviderID());
            return;
        }

        // Everything looks good.
        D content = D.createNode("div", "class", "main");

        cert.setVerifyTimestamp(System.currentTimeMillis());

        D prenotice;

        if (nop.getType() == CNonceOp.Type.ADD) {
            cert.setProfileImage(pinfo.getProfileImage());
            cert.setProviderDisplayName(pinfo.getProviderDisplayName());
            CVerifyCertificate.storeInfo(cert);
            content.addChild(U.format(cert, false));
            prenotice = D.createNode
                ("div", "class", "prenotice")
                .addChild
                (D.wrapText
                 ("p",
                  "Congratulations, you have successfully verified and added your public key. Here is a shareable link to your public key.<br/><input class='keylink' type='text' spellcheck='false' autocorrect='off' readonly='readonly' value='https://pgpauth.appspot.com/pks/lookup?q="+cert.getFingerprint()+"'>"));
        }
        else {
            CVerifyCertificate.removeInfo(cert);
            prenotice = D.createNode
                ("div", "class", "prenotice")
                .addChild
                (D.wrapText
                 ("p",
                  "Congratulations, you have successfully removed your key."));
        }

        String donelink = makeReturnLink(cert, nop);

        prenotice
            .addChild
            (D.createNode("div", "class", "abuttons")
             .addChild
             (D.createNode("a", "class", "ok", "href", donelink)
              .addChild
              (D.createText("Done"))));

        content.addChild(prenotice);

        if (nop.getType() == CNonceOp.Type.ADD) {
            D.dumpContent
                (resp.getWriter(), "OpenPGPAuth", content,
                 "/static/js/isel.js");
        }
        else {
            D.dumpContent
                (resp.getWriter(), "OpenPGPAuth", content);
        }            
    }

    private final static String makeReturnLink
        (CVerifyCertificate.Info cert, CNonceOp nop)
        throws IOException
    {
        CUserID uid = cert.getID();
        // AProvider provider = uid.getProvider();
        String ret;
        if (nop.getCbURL() == null) {
            //donelink = "/pks/lookup?header=yes&q="+
            //    provider.getProfileQueryFor(uid.getProviderID());
            ret = "/";
        }
        else {
            String cbstate = nop.getCbState();
            ret = nop.getCbURL().toString()+"?status=ok";
            if (!Utils.isEmpty(cbstate)) {
                ret += "&cbstate="+URLEncoder.encode(cbstate, "utf-8");
            }
        }
        return ret;
    }

    private final static Logger s_logger =
        Logger.getLogger(COAuthResponseServlet.class.getName());
}
