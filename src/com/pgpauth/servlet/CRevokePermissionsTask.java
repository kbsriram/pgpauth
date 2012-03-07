package com.pgpauth.servlet;

/*
 * When possible, we also revoke any permissions we obtained via
 * OAuth right away.
 *
 * This data for this task is enqueued by a provider at the end of any
 * successful key addition, and is passed back to it here to do whatever
 * it needs to do.
 */

import com.pgpauth.common.D;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CUserID;

import com.pgpauth.provider.AProvider;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

import java.util.logging.Logger;
import java.util.logging.Level;

@SuppressWarnings("serial")
public class CRevokePermissionsTask
    extends HttpServlet
{
    @Override
    protected void doPost
        (HttpServletRequest req, HttpServletResponse resp)
        throws IOException
    {
        String t = req.getParameter(AProvider.REVOKE_TYPE);
        s_logger.log(Level.INFO, "revoking permissions for: '"+t+"'");
        AProvider p = AProvider.forType(t);
        if (p == null) {
            s_logger.log(Level.INFO, "Hm, no provider found? strange");
            return;
        }

        p.revoke(req);
    }

    private final static Logger s_logger =
        Logger.getLogger(CRevokePermissionsTask.class.getName());
}
