package com.pgpauth.servlet;

import com.pgpauth.provider.AProvider;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

@SuppressWarnings("serial")
public class CStartupServlet
    extends HttpServlet
{
    @Override
    public void init(ServletConfig cfg)
        throws ServletException
    {
        // Prime the providers from property files.
        try { AProvider.init(); }
        catch (IOException ioe) {
            throw new ServletException(ioe);
        }
    }
}
