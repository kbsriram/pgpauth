package com.pgpauth.common;

// Simple class to let me ship out html fragments
// Each D instance is a node in an HTML tree.

import java.io.PrintWriter;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedList;

public class D
{
    // wrap this fragment into an html wrapper and slap
    // on some chrome on everything.

    public static void dumpContent
        (PrintWriter pw, String title, D content, String... scripts)
        throws IOException
    {
        D html = createNode("html", "lang", "en");

        D head = createNode("head")
            .addChild
            (createNode("meta", "charset", "utf-8"))
            .addChild
            (createNode("meta", "http-equiv", "X-UA-Compatible",
                        "content", "IE=edge,chrome=1"))
            .addChild
            (createNode("meta", "name", "viewport",
                        "content", "width=device-width,initial-scale=1.0"))
            .addChild
            (createNode("meta", "name", "apple-mobile-web-app-capable",
                        "content", "yes"))
            .addChild
            (createNode("meta", "name", "format-detection",
                        "content", "telephone=no"))

            .addChild
            (createNode("link", "rel", "stylesheet",
                        "href", "/static/css/master.css",
                        "type", "text/css"));

        if (scripts.length > 0) {
            head.addChild
                (createNode("script", "type", "text/javascript",
                            "src", "/static/js/jquery-1.6.3.min.js"));

            for (int si=0; si<scripts.length; si++) {
                head.addChild
                    (createNode("script", "type", "text/javascript",
                                "src", scripts[si]));
            }
        }

        head.addChild(D.createNode("title")
                      .addChild(createText(title)));

        html.addChild(head);

        D body = D.createNode("body")
            .addChild(content);

        html.addChild(body);
        pw.println("<!doctype html>");
        dumpRoot(pw, html);
    }

    public final static D createNode(String name, String... atts)
    {
        int max = atts.length;
        if ((max % 2) == 1) {
            throw new IllegalArgumentException("Expecting even number of attribute vals");
        }
        D ret = new D(name, false, null);
        int idx = 0;
        while (idx < max) {
            ret.setAttribute(atts[idx++], atts[idx++]);
        }
        return ret;
    }

    public final static D createText(String content)
    { return new D(null, true, content); }

    public final static D wrapText(String n, String content)
    {
        return createNode(n)
            .addChild(createText(content));
    }

    public D setAttribute(String name, String value)
    {
        if (m_istext) {
            throw new RuntimeException("unexpected "+name+"="+value);
        }
        m_attrs.put(name, value);
        return this;
    }

    public D addChild(D child)
    {
        if (m_istext) {
            throw new RuntimeException("Unexpected adding child ");
        }
        m_children.add(child);
        return this;
    }

    public String getContent()
    { return m_content; }

    public List<D> getChildren()
    { return m_children; }

    public Map<String,String> getAttributes()
    { return m_attrs; }

    public String getName()
    { return m_name; }

    public boolean isText()
    { return m_istext; }

    public final static void dumpRoot(PrintWriter pw, D root)
    {
        if (root.isText()) {
            pw.print(root.getContent());
            return;
        }

        pw.print("<");
        pw.print(root.getName());
        Map<String,String> attrs = root.getAttributes();
        if (attrs.size() > 0) {
            for (String attribute: attrs.keySet()) {
                pw.print(" ");
                pw.print(attribute);
                pw.print("=\"");
                pw.print(attrEncode(attrs.get(attribute)));
                pw.print("\"");
            }
        }
        List<D> children = root.getChildren();
        if (children.size() > 0) {
            // Avoid whitespace in some situations.
            if (s_no_ws.contains(root.getName())) {
                pw.print(">");
            }
            else {
                pw.println(">");
            }
            for (D child: children) {
                dumpRoot(pw, child);
            }
            pw.print("</");
            pw.print(root.getName());
            pw.print(">");            
        }
        else {
            if (root.getName().equals("div") ||
                root.getName().equals("a") ||
                root.getName().equals("script")) { // this needs special care
                pw.print("></"+root.getName()+">");
            }
            else {
                pw.print(" />");
            }
        }
    }

    private D(String name, boolean istext, String content)
    {
        m_name = name;
        m_istext = istext;
        m_content = content;
    }

    private final static String attrEncode(String in)
    {
        char v[] = in.toCharArray();
        StringBuilder ret = new StringBuilder();
        for (int i=0; i<v.length; i++) {
            char cur = v[i];
            if (cur == '<') {
                ret.append("&lt;");
            }
            else if (cur == '&') {
                ret.append("&amp;");
            }
            else if (cur == '"') {
                ret.append("&quot;");
            }
            else {
                ret.append(cur);
            }
        }
        return ret.toString();
    }

    private final String m_name;
    private final String m_content;
    private final boolean m_istext;
    private final Map<String,String> m_attrs = new HashMap<String,String>();
    private final List<D> m_children = new LinkedList<D>();
    private final static Set<String> s_no_ws;
    static
    {
        s_no_ws = new HashSet<String>();
        s_no_ws.add("uri");
        s_no_ws.add("id");
        s_no_ws.add("updated");
        s_no_ws.add("published");
        s_no_ws.add("title");
        s_no_ws.add("icon");
        s_no_ws.add("name");
        s_no_ws.add("dc:creator");
    }
}
