package com.pgpauth.common;

import com.pgpauth.provider.AProvider;
import java.io.Serializable;

public class CUserID
    implements Serializable
{
    static final long serialVersionUID = 1488020416746726133L;

    public CUserID
        (String orig, String pid, String dn, String c, AProvider provider)
    {
        m_orig = orig;
        m_pid = pid;
        m_dn = dn;
        m_comment = c;
        m_provider = provider;
    }
    public AProvider getProvider()
    { return m_provider; }
    public String getOriginal()
    { return m_orig; }
    public String getProviderID()
    { return m_pid; }
    public String getDisplayName()
    { return m_dn; }
    public String getComment()
    { return m_comment; }
    public String getType()
    { return m_provider.getType(); }
    public String getProfileLink()
    { return m_provider.getProfileLinkFor(m_pid); }
    public String getProfileLinkName()
    { return m_provider.getProfileLinkNameFor(m_pid); }

    private final AProvider m_provider;
    private final String m_orig;
    private final String m_pid;
    private final String m_dn;
    private final String m_comment;
}
