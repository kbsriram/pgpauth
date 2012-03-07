package com.pgpauth.servlet;

import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CVerifyCertificate;
import com.pgpauth.common.CNonceOp;
import com.pgpauth.provider.AProvider;

import java.util.List;
import java.net.URL;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServlet;
import java.util.logging.Logger;
import java.util.logging.Level;

@SuppressWarnings("serial")
public class CDelCertificateServlet
    extends AOpCertificateServlet
{
    @Override
    protected CVerifyCertificate.Info getCertificate
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        String fp = req.getParameter("fp");
        if ((fp == null) ||
            fp.length() == 0) {
            U.forbid(req, resp, "Missing fp paramater");
            return null;
        }

        String cfp = canonical(fp);
        if (cfp == null) {
            U.forbid(req, resp, "Bad fingerprint format '"+fp+"'");
            return null;
        }

        // First make sure we actually have this certificate.
        CVerifyCertificate.Info vc =
            CVerifyCertificate.lookupByFingerprint(cfp);
        if (vc == null) {
            U.forbid(req, resp, "No such fingerprint.");
            return null;
        }
        return vc;
    }

    @Override
    protected CNonceOp.Type getOpType()
    { return CNonceOp.Type.DEL; }

    @Override
    protected D makeContent
        (CVerifyCertificate.Info info, String refer,
         String ok_url, String cancel_url)
    {
        AProvider provider = info.getID().getProvider();
        String sitename = provider.getSiteName();

        StringBuilder sb = new StringBuilder();
        if ("pgpauth.appspot.com".equals(refer)) {
            sb.append("You are");
        }
        else {
            sb.append("<span class='warn'>"+refer+"</span> is");
        }
        sb.append(" about to <span class='warn'>remove</span> this public key. OpenPGPAuth can remove it after verifying with <span class='rprovider'>"+sitename+"</span> whether you are permitted to do it.");

        // Build up disclosure data.
        D disclosure = provider.getDisclosure(info.getID(), getOpType());

        D ret = D
            .createNode("div", "class", "prenotice")
            .addChild
            (D.wrapText("p", sb.toString()))
            .addChild
            (D.createNode("p")
             .addChild
             (D.createNode("a", "class", "info_toggle")
              .addChild
              (D.createText("What does \"verify\" mean?"))))
            .addChild(disclosure)
            .addChild
            (D.createNode("div", "class", "abuttons")
             .addChild
             (D.createNode("a", "class", "cancel", "href", cancel_url)
              .addChild(D.createText("Cancel")))
             .addChild
             (D.createNode("a", "class", "ok", "href", ok_url)
              .addChild(D.createText("Verify and Remove"))));
        return ret;
    }


    private final static String canonical(String s)
    {
        StringBuilder sb = new StringBuilder();
        char[] chars = s.toCharArray();
        for (int i=0; i<chars.length; i++) {
            char c = chars[i];
            if (((c >= 'a') && (c <= 'f')) ||
                ((c >= '0') && (c <= '9'))) {
                sb.append(c);
            }
            else if ((c >= 'A') && (c <= 'F')) {
                sb.append(Character.toLowerCase(c));
            }
            else if ((c == ' ') || (c == '\t') ||
                     (c == '\r') || (c == '\n')) {
                // skip
            }
            else {
                return null;
            }
        }
        return sb.toString();
    }
}
