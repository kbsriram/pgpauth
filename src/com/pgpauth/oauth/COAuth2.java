package com.pgpauth.oauth;

// Grab bag for OAuth2 utilities.

import com.pgpauth.provider.AProviderInfo;
import com.pgpauth.common.Utils;
import com.pgpauth.common.CNonceOp;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.net.URL;
import java.net.MalformedURLException;
import javax.servlet.http.HttpServletRequest;

public class COAuth2
{
    public static AProviderInfo checkErrors
        (CNonceOp nop, HttpServletRequest req)
    {
        // 0. Check referer
        AProviderInfo ret = COAuth1a.checkReferer(nop, req);
        if (ret != null) {
            return ret;
        }

        // 1. Verify state.
        String state = req.getParameter("state");
        if (state == null) {
            return new ErrorInfo
                (AProviderInfo.State.ERROR, "session state is missing");
        }

        // 2. Nonces should be identical.
        if (!state.equals(nop.getNonce())) {
            return new ErrorInfo
                (AProviderInfo.State.ERROR, "unable to verify session");
        }

        // 3. Now check for oauth errors.
        String error = req.getParameter("error");
        if ("access_denied".equals(error)) {
            return new ErrorInfo
                (AProviderInfo.State.CANCEL, "User cancelled operation");
        }
        if (error != null) {
            return new ErrorInfo
                (AProviderInfo.State.ERROR, error);
        }

        // 4. Ensure we have an access code
        if (Utils.isEmpty(req.getParameter("code"))) {
            return new ErrorInfo
                (AProviderInfo.State.ERROR, "sorry, missing token");
        }
        return null;
    }

    public final static class ErrorInfo
        extends AProviderInfo
    {
        private ErrorInfo(AProviderInfo.State s, String msg)
        {
            super(s, msg, null, null, null);
        }
    }

    private final static Logger s_logger =
        Logger.getLogger(COAuth2.class.getName());
}
