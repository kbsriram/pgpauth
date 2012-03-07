package com.pgpauth.servlet;

import com.pgpauth.common.Utils;
import com.pgpauth.common.D;
import com.pgpauth.common.CVerifyCertificate;
import com.pgpauth.common.CUserID;

import org.json.JSONObject;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.io.IOException;
import java.io.Serializable;
import java.io.PrintWriter;
import java.net.URL;

public class U
{
    final static void forbid(HttpServletRequest req,
                             HttpServletResponse resp,
                             String msg)
        throws IOException
    { err(HttpServletResponse.SC_FORBIDDEN, req, resp, msg); }

    final static void notimplemented
        (HttpServletRequest req,
         HttpServletResponse resp,
         String msg)
        throws IOException
    { err(HttpServletResponse.SC_NOT_IMPLEMENTED, req, resp, msg); }

    final static void notfound(HttpServletRequest req,
                             HttpServletResponse resp,
                             String msg)
        throws IOException
    { err(HttpServletResponse.SC_NOT_FOUND, req, resp, msg); }

    final static void err
        (int code, HttpServletRequest req,
         HttpServletResponse resp, String msg)
        throws IOException
    {
        boolean isjs = "json".equals(req.getParameter("f"));
        if (!isjs) {
            resp.sendError(code, msg);
            return;
        }

        JSONObject j = new JSONObject();
        j.put("error", msg);

        String cb = req.getParameter("callback");
        PrintWriter pw = resp.getWriter();

        if (Utils.isEmpty(cb)) {
            resp.setContentType("application/json");
            j.write(pw);
            return;
        }

        if (!JSON_FUNCTION.matcher(cb).matches()) {
            throw new IOException("Invalid callback name: "+cb);
        }
        resp.setContentType("application/javascript");
        pw.print(cb);
        pw.print("(");
        j.write(pw);
        pw.print(");");
    }

    // a boilerplate header, and optional value for the searchbox
    final static D header(String qval)
    {
        D ret = D.createNode("div", "class", "header");

            // header title
        ret.addChild
            (D.createNode("div", "class", "htitle")
             .addChild
             (D.createNode("a", "href", "/")
              .addChild(D.createText("OpenPGPAuth"))))

            // links to assorted stuff
            .addChild
            (D.createNode("div", "class", "hlinks")
             .addChild
             (D.createNode("div", "class", "hlink br")
              .addChild
              (D.createNode("a", "href", "/")
               .addChild(D.createText("Search"))))
             .addChild
             (D.createNode("div", "class", "hlink br")
              .addChild
              (D.createNode("a", "href", "/add.html")
               .addChild(D.createText("Add a key"))))
             .addChild
             (D.createNode("div", "class", "hlink br")
              .addChild
              (D.createNode("a", "href", "/del.html")
               .addChild(D.createText("Remove a key"))))
             .addChild
             (D.createNode("div", "class", "hlink br")
              .addChild
              (D.createNode("a", "href", "/api.html")
               .addChild(D.createText("API"))))
             .addChild
             (D.createNode("div", "class", "hlink")
              .addChild
              (D.createNode("a", "href", "/about.html")
               .addChild(D.createText("About")))));

        // searchbox
        D sinput = D.createNode
            ("input", "autocomplete", "off",
             "autocorrect", "off",
             "spellcheck", "false",
             "placeholder", "Search by email, profile or keyid",
             "name", "q",
             "type", "text");

        if (!Utils.isEmpty(qval)) {
            sinput.setAttribute("value", qval);
        }

        ret.addChild
            (D.createNode("div", "class", "searchbox")
             .addChild
             (D.createNode("form", "method", "post", "action", "/pks/lookup")
              .addChild(sinput)
              .addChild
              (D.createNode("input", "type", "hidden",
                            "name", "header",
                            "value", "yes"))));
        return ret;
    }


    // A nicely formatted view of a certificate.
    final static D format(CVerifyCertificate.Info vc, boolean dlinkp)
    { return format(vc, dlinkp, false); }

    final static D format
        (CVerifyCertificate.Info vc, boolean dlinkp, boolean plinkp)
    {
        CUserID uid = vc.getID();

        D umain = D.createNode("div", "class", "user_main vcard");
        if (vc.getProfileImage() != null) {
            umain.addChild
                (D.createNode("div", "class", "user_icon")
                 .addChild(D.createNode
                           ("img", "class", "photo",
                            "src", vc.getProfileImage())));
        }
        D uinfo = D.createNode("div", "class", "user_info")
            .addChild
            (D.createNode("b", "class", "fn")
             .addChild
             (D.createText(safe(uid.getDisplayName()))));
        umain.addChild(uinfo);

        if (!Utils.isEmpty(uid.getComment())) {
            uinfo.addChild
                (D.wrapText("p", safe(trunc(uid.getComment(), 80))));
        }

        D dlink_url = D.createNode
            ("a", "rel", "me",
             "href", uid.getProfileLink(),
             "title", vc.getProviderDisplayName(true))
            .addChild
            (D.createNode("span", "class", "role")
             .addChild
             (D.createText
              (safe(uid.getProfileLinkName()))));

        // add vcard disambiguation between emails and profile links.
        if (uid.getProfileLink().startsWith("mailto:")) {
            dlink_url.setAttribute("class", "email");
        }
        else {
            dlink_url.setAttribute("class", "url");
        }

        uinfo.addChild
            (D.createNode("p")
             .addChild
             (D.createNode
              ("img", "class", "org picon",
               "title", uid.getProvider().getSiteName(),
               "alt", uid.getProvider().getSiteName(),
               "src", "/static/css/"+uid.getType()+".png"))
             .addChild(dlink_url));

        if (vc.getVerifyTimestamp() > 0) {
            SimpleDateFormat sdf = new SimpleDateFormat("MMM d, yyyy");
            uinfo
                .addChild
                (D.createNode("div", "class", "verify_ts")
                 .addChild(D.createText
                           ("Verified on "+
                            sdf.format(new Date(vc.getVerifyTimestamp())))));
        }

        D uextra = D.createNode("div", "class", "user_extra");
        uextra
            .addChild
            (D.createNode("div", "class", "fp")
             .addChild(D.createText(fcsplit(vc.getFingerprint()))));

        // assemble the bits back.
        D ret =
            D.createNode("div", "class", "certificate")
            .addChild(umain)
            .addChild(uextra);
        if (!dlinkp) { return ret; }

        D cert_links =
            D.createNode("div", "class", "certificate_links");

        if (plinkp) {
            cert_links
                .addChild
                (D.createNode
                 ("a", "href", "/pks/lookup?q="+vc.getFingerprint())
                 .addChild
                 (D.createText("permalink")));
        }
        cert_links
            .addChild
            (D.createNode
             ("a", "class", "download_key",
              "href", "/pks/lookup?f=pgp&q="+vc.getFingerprint())
             .addChild
             (D.createText("Download PGP key")));

        return D.createNode("div")
            .addChild(ret)
            .addChild(cert_links);
    }

    // Break up string into chunks of 4, and insert
    // a <br/> every 5 chunks
    private final static String fcsplit(String fp)
    {
        char chars[] = fp.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<chars.length; i++) {
            if (i == 0) { sb.append(chars[i]); continue; }
            if ((i % 20) == 0) {
                sb.append("<br/>");
            }
            else if ((i % 4) == 0) {
                sb.append(" ");
            }
            sb.append(chars[i]);
        }
        return sb.toString();
    }

    // upto n characters.
    private final static String trunc(String in, int max)
    {
        if (Utils.isEmpty(in)) { return in; }
        if (in.length() < max) { return in; }
        return in.substring(0, max-3)+"...";
    }

    // encode everything here
    public final static String safe(String in)
    {
        if ((in == null) || (in.length() == 0)) {
            return "";
        }
        char chars[] = in.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<chars.length; i++) {
            char c = chars[i];
            // pass through some stuff.
            if (((c >= 'a') && (c <= 'z')) ||
                ((c >= 'A') && (c <= 'Z')) ||
                (c == ' ') || (c == '\r') || (c == '\n') || (c == '\t') ||
                ((c >= '0') && (c <= '9')) ||
                (c == '(') || (c == ')') ||
                (c == '.') || (c == '_') || (c == '-')) {
                sb.append(c);
            }
            else {
                // encode.
                sb.append("&#");
                sb.append(Integer.toString(c));
                sb.append(";");
            }
        }
        return sb.toString();
    }

    final static void dumpJSON
        (JSONObject json, HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        String cb = req.getParameter("callback");
        boolean isjson = !Utils.isEmpty(cb);
        PrintWriter pw = resp.getWriter();
        if (isjson) {
            // Do a spot check. Only permit single function
            // definitions, or object.function
            if (!JSON_FUNCTION.matcher(cb).matches()) {
                throw new IOException("Invalid callback name: "+cb);
            }
            resp.setContentType("application/javascript");
            pw.print(cb);
            pw.print("(");
            json.write(pw);
            pw.print(");");
        }
        else {
            resp.setContentType("application/json");
            json.write(pw);
        }
    }

    final static void addSecureCookie
        (HttpServletResponse resp,
         String cname, String cval)
        throws IOException
    {

        /*
        Cookie cookie = new Cookie(cname, cval);
        cookie.setHttpOnly(true);
        if (Utils.isProduction()) {
            cookie.setSecure(true);
        }
        resp.addCookie(cookie);
        */

        // Directly use header to allow setting http-only flag
        StringBuilder sb =
            new StringBuilder(cname);
        sb.append("=");
        sb.append(cval);
        if (Utils.isProduction()) {
            sb.append("; secure");
        }
        sb.append("; path=/; HttpOnly");
        resp.addHeader("Set-Cookie", sb.toString());
    }

    final static String removeCookie
        (HttpServletRequest req,
         HttpServletResponse resp,
         String cname, String path)
        throws IOException
    {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) { return null; }

        String ret = null;
        for (int i=0; i<cookies.length; i++) {
            Cookie cookie = cookies[i];
            if (cname.equals(cookie.getName())) {
                ret = cookie.getValue();
                Cookie r = (Cookie) (cookie.clone());
                r.setPath("/");
                r.setMaxAge(0);
                resp.addCookie(r);
            }
        }
        return ret;
    }

    private final static Pattern JSON_FUNCTION =
        Pattern.compile("[a-zA-Z0-9_\\.]+");

}
