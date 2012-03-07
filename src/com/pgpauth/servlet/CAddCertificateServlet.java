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
public class CAddCertificateServlet
    extends AOpCertificateServlet
{
    @Override
    protected CVerifyCertificate.Info getCertificate
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        String pkblock = req.getParameter("pubkey");
        if ((pkblock == null) ||
            pkblock.length() == 0) {
            U.forbid(req, resp, "Missing pubkey parameter");
            return null;
        }

        // We don't want to accept ginormous keys either.
        if (pkblock.length() > 100*1024) {
            U.forbid(req, resp, "Sorry -- this key looks way too big.");
            return null;
        }

        // Check if we've got something that we think
        // we want to handle.
        try {
            return CVerifyCertificate.getInfo(pkblock, true);
        }
        catch (CVerifyCertificate.NotHandledException ne) {
            s_logger.log(Level.INFO, "Rejecting certificate: "+ne.getMessage());
            notHandled(resp, ne.getMessage());
            return null;
        }
        catch (CVerifyCertificate.BadException be) {
            // TBD: Handle this with a nicer error message, rather
            // than a plain forbidden.
            s_logger.log(Level.INFO, "Failed to verify certificate", be);
            U.forbid(req, resp, be.getMessage());
            return null;
        }
    }

    @Override
    protected CNonceOp.Type getOpType()
    { return CNonceOp.Type.ADD; }


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
        sb.append(" about to add your public key to an online database. This lets anyone create encrypted material that only you can read. OpenPGPAuth can add your key after verifying the information in it with <span class='rprovider'>"+sitename+"</span>.");

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
              .addChild(D.createText("No thanks")))
             .addChild
             (D.createNode("a", "class", "ok", "href", ok_url)
              .addChild(D.createText("Verify and Add"))));
        return ret;
    }

    private final static void notHandled
        (HttpServletResponse resp, String userid)
        throws IOException
    {
        D content = D.createNode("div", "class", "main")
            .addChild
            (D.createNode
             ("div", "class", "prenotice")
             .addChild
             (D.wrapText
              ("p",
               "Oops! Your PGP key has the User ID<br/><tt class='warn'>"+
               U.safe(userid)+"</tt>"))
             .addChild
             (D.createNode("p", "style", "margin-top: 1em")
              .addChild
              (D.createText
               ("I only handle keys with User IDs that contain<br/>"+
                "<tt>&lt;user@gmail.com&gt;</tt><br/>"+
                "<tt>&lt;user@yahoo.com&gt;</tt><br/>"+
                "<tt>&lt;https://twitter.com/user&gt;</tt><br/>"+
                "<tt>&lt;https://www.facebook.com/id&gt;</tt><br/>"+
                "<tt>&lt;https://plus.google.com/id&gt;</tt>")))
             .addChild
             (D.createNode("div", "class", "abuttons")
              .addChild
              (D.createNode("a", "class", "ok", "href",
                            "javascript:history.back()")
               .addChild
               (D.createText("Go Back")))));

        D.dumpContent
            (resp.getWriter(), "OpenPGPAuth", content);
    }

    private final static Logger s_logger =
        Logger.getLogger(CAddCertificateServlet.class.getName());

}
