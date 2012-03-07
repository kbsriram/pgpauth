package com.pgpauth.servlet;

import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CVerifyCertificate;
import com.pgpauth.common.CUserID;

import com.pgpauth.provider.AProvider;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.ByteArrayInputStream;
import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPException;

import org.json.JSONObject;
import org.json.JSONArray;

import java.util.List;
import java.util.ArrayList;
import java.util.Enumeration;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.math.BigInteger;

@SuppressWarnings("serial")
public class CLookupServlet
    extends HttpServlet
{
    @Override
    protected void service
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {

        // Analyze the request and handle a few different
        // formats.
        String q = req.getParameter("q");
        if (!Utils.isEmpty(q)) {
            handleQ(req, resp, q);
            return;
        }

        String op = req.getParameter("op");
        String search = req.getParameter("search");
        if (!Utils.isEmpty(op) && !Utils.isEmpty(search)) {
            handleHKP(req, resp, op, search);
            return;
        }
        U.notfound(req, resp, "Missing query");
    }

    private final static void handleQ
        (HttpServletRequest req, HttpServletResponse resp, String q)
        throws IOException
    {
        List<String> fps = null;

        // First try to see if it's a user-id string.
        CUserID uid = AProvider.fromString(q);
        if (uid != null) {
            fps = CVerifyCertificate.lookupByID(uid);
        }
        else {
            // see if it looks like a keyid or a fingerprint.
            String val = asNumber(q);
            if (val != null) {
                // The number is treated as a keyid if it is "small"
                if (val.length() <= 8) {
                    fps = CVerifyCertificate.lookupByKeyID
                        ((new BigInteger(val, 16)).longValue());
                }
                else {
                    // otherwise, as a fingerprint.
                    fps = asList(CVerifyCertificate.lookupByFingerprint(val));
                }
            }
        }

        boolean headerp = "yes".equals(req.getParameter("header")) &&
            Utils.isEmpty(req.getParameter("f"));

        // return a 404 if we don't need to add headers, and we
        // didn't find anything.
        if (!headerp && ((fps == null) || (fps.size() == 0))) {
            U.notfound(req, resp, "No keys found for '"+q+"'");
            return;
        }

        // Here we return content based on the format type.
        String s = req.getParameter("f");
        if (Utils.isEmpty(s)) {
            dumpD(q, fps, req, resp, headerp);
        }
        else if ("pgp".equals(s)) {
            dumpPGP(fps, req, resp);
        }
        else if ("json".equals(s)) {
            dumpJSON(fps, req, resp);
        }
        else {
            U.notfound(req, resp, "No such format: '"+s+"'");
        }
    }

    private final static List<String> asList(CVerifyCertificate.Info cert)
    {
        if (cert == null) { return null; }
        List<String> ret = new ArrayList<String>();
        ret.add(cert.getFingerprint());
        return ret;
    }

    private final static void dumpJSON
        (List<String> fps, HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        JSONObject j = new JSONObject();
        JSONArray ja = new JSONArray();
        for (String fp: fps) {
            CVerifyCertificate.Info cert =
                CVerifyCertificate.lookupByFingerprint(fp);
            JSONObject jc = new JSONObject();
            CUserID uid = cert.getID();
            if (!Utils.isEmpty(cert.getProfileImage())) {
                jc.put("picture", cert.getProfileImage());
            }
            jc.put("name_certificate", uid.getDisplayName());
            if (!Utils.isEmpty(uid.getComment())) {
                jc.put("comment", uid.getComment());
            }
            jc.put("link", uid.getProfileLink());
            jc.put("name_provider", cert.getProviderDisplayName(true));
            if (cert.getVerifyTimestamp() > 0) {
                jc.put("verified", cert.getVerifyTimestamp());
            }
            jc.put("fingerprint", cert.getFingerprint());
            ja.put(jc);
        }

        j.put("keys", ja);
        U.dumpJSON(j, req, resp);
    }

    private final static void dumpD
        (String q, List<String> fps,
         HttpServletRequest req, HttpServletResponse resp, boolean headerp)
        throws IOException
    {
        D content = D.createNode("div", "class", "main");
        if (headerp) {
            content.addChild(U.header(q));
        }

        D certificates = D.createNode("div", "class", "certificates");
        content.addChild(certificates);

        String title = null;

        if ((fps == null) || (fps.size() == 0)) {
            content.addChild
                (D.createNode("div", "class", "prenotice")
                 .addChild
                 (D.wrapText("p", "No results found")));
            /*
                 .addChild
                 (D.createNode("div", "class", "searchexamples")
                  .addChild
                  (D.wrapText("p", "Example queries:"))
                  .addChild
                  (D.wrapText("p", "<tt>username@yahoo.com</tt>"))
                  .addChild
                  (D.wrapText("p", "<tt>username@gmail.com</tt>"))
                  .addChild
                  (D.wrapText("p", "<tt>https://twitter.com/name</tt>"))
                  .addChild
                  (D.wrapText("p", "<tt>https://facebook.com/id</tt>"))
                  .addChild
                  (D.wrapText("p", "<tt>https://plus.google.com/id</tt>"))));
            */
        }
        else {
            for (String fp: fps) {
                CVerifyCertificate.Info cert = CVerifyCertificate
                    .lookupByFingerprint(fp);
                certificates.addChild
                    (U.format(cert, true, headerp));
                if (title == null) {
                    String dn = cert.getID().getDisplayName();
                    if (dn != null) {
                        title = "PGP Key for "+U.safe(dn);
                    }
                }
            }
        }
        if (title == null) {
            title = "Search | OpenPGPAuth";
        }
        else {
            title = title + "| OpenPGPAuth";
        }
        D.dumpContent(resp.getWriter(), title, content);
    }

    private final static void dumpPGP
        (List<String> fps, HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        resp.setContentType("application/pgp-keys");
                       
        // Easy case -- just dump out the original key.
        if (fps.size() == 1) {
            String fp = fps.get(0);
            resp.setHeader("Content-Disposition",
                           "attachment;filename="+fp+".asc");

            PrintWriter pw = resp.getWriter();
            CVerifyCertificate.Info cert =
                CVerifyCertificate.lookupByFingerprint(fp);
            pw.print(cert.getCertificateData());
            return;
        }

        resp.setHeader("Content-Disposition",
                       "attachment;filename=OpenPGPAuthKeys.asc");
        // Encode each key.
        ArmoredOutputStream aout =
            new ArmoredOutputStream(resp.getOutputStream());
        for (String fp: fps) {
            CVerifyCertificate.Info cert =
                CVerifyCertificate.lookupByFingerprint(fp);
            PGPPublicKeyRingCollection pkrc;
            try {
                
                pkrc = new PGPPublicKeyRingCollection
                    (PGPUtil.getDecoderStream
                     (new ByteArrayInputStream
                      (cert.getCertificateData().getBytes("utf-8"))));
            }
            catch (PGPException pge) {
                throw new IOException(pge);
            }
            pkrc.encode(aout);
        }
        aout.close();
    }

    private final static void dumpHKP
        (List<String> fps, HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        resp.setContentType("text/plain");
        PrintWriter pw = resp.getWriter();

        pw.println("info:1:"+fps.size());

        for (String fp: fps) {
            CVerifyCertificate.Info cert =
                CVerifyCertificate.lookupByFingerprint(fp);
            pw.println("pub:"+fp+":::::");
            pw.println("uid:"+escape(cert.getID().getOriginal())+":::");
        }
    }

    // HTML encoded, but only for non-7bit-ish chars
    private final static String escape(String in)
    {
        StringBuilder sb = new StringBuilder();
        char[] chars = in.toCharArray();
        for (int i=0; i<chars.length; i++) {
            char c = chars[i];
            if ((c >= ' ') && (c <= '~') && (c != ':')) {
                sb.append(c);
            }
            else {
                sb.append("%"+(Integer.toHexString(c)).toUpperCase());
            }
        }
        return sb.toString();
    }


    // return a (space-stripped, lowercase) hex string
    // if the input is also a hex string
    private final static String asNumber(String s)
    {
        if (Utils.isEmpty(s)) { return null; }
        StringBuilder sb = new StringBuilder();
        char[] chars = s.toCharArray();
        for (int i=0; i<chars.length; i++) {
            char c = chars[i];
            if (((c >= '0') && (c <= '9')) ||
                ((c >= 'a') && (c <= 'f')) ||
                ((c >= 'A') && (c <= 'F'))) {
                sb.append(c);
                continue;
            }
            if ((c == ' ') || (c == '\t') ||
                (c == '\r') || (c == '\n')) {
                continue;
            }
            // reject everything else.
            return null;
        }
        return sb.toString();
    }

    private final static void handleHKP
        (HttpServletRequest req, HttpServletResponse resp, String op,
         String search)
        throws IOException
    {
        // we only support a few types of operations. Per the spec,
        // return a not-implemented if we can't grok it.

        s_logger.log(Level.INFO, "HKP: op="+op+",search="+search);

        // 1) Only support machine-readable queries.
        String s = req.getParameter("options");
        if (Utils.isEmpty(s)) {
            s_logger.log(Level.INFO, "Rejecting HKP: no mr options");
            U.notimplemented
                (req, resp, "Sorry, only support machine-readable HKP");
            return;
        }
        String options[] = s.split(",");
        boolean ok = false;
        for (int i=0; i<options.length; i++) {
            if (options[i].equals("mr")) { ok = true; break; }
        }
        if (!ok) {
            s_logger.log
                (Level.INFO, "Rejecting HKP: options="+s);
            U.notimplemented
                (req, resp, "Sorry, only support machine-readable HKP");
            return;
        }

        // 2) Only support "get" or "index" operations.
        boolean isget = "get".equals(op);
        if (!isget) {
            if (!"index".equals(op)) {
                s_logger.log
                    (Level.INFO, "Rejecting HKP-op: "+op);
                U.notimplemented
                    (req, resp, "Sorry, only support get or index operations");
                return;
            }
        }

        List<String> fps = null;
        // Now start parsing the search variable.
        if (search.startsWith("0x")) {
            // keyid or fingerprint. We assume that a length
            // <= 8 means a keyid.
            String hs = search.substring(2);
            if (hs.length() <= 8) {
                fps = CVerifyCertificate.lookupByKeyID
                    ((new BigInteger(hs, 16)).longValue());
            }
            else {
                fps = asList(CVerifyCertificate.lookupByFingerprint(hs));
            }
        }
        else {
            // We assume we have an exact match search. NB: GPG seems to
            // append a spurious > symbol at the very end. hm.
            if (search.endsWith(">")) {
                search = search.substring(0, search.length()-1);
            }
            CUserID uid = AProvider.fromString(search);
            if (uid != null) {
                fps = CVerifyCertificate.lookupByID(uid);
            }
        }

        if ((fps == null) || (fps.size() == 0)) {
            U.notfound(req, resp, "No keys for '"+search+"'");
            return;
        }

        if (isget) {
            // dump armored pgp keys
            dumpPGP(fps, req, resp);
        }
        else {
            dumpHKP(fps, req, resp);
        }
    }

    private final static Logger s_logger =
        Logger.getLogger(CLookupServlet.class.getName());

}
