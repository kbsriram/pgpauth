package com.pgpauth.provider;

public abstract class AProviderInfo
{
    public enum State { CANCEL, ERROR, OK };

    protected AProviderInfo
        (State s, String msg, String pid, String pdn, String ppic)
    {
        m_s = s;
        m_msg = msg;
        m_pid = pid;
        m_pdn = pdn;
        m_ppic = ppic;
    }

    public State getState()
    { return m_s; }
    public String getMessage()
    { return m_msg; }
    public String getProviderID()
    { return m_pid; }
    public String getProviderDisplayName()
    { return m_pdn; }
    public String getProfileImage()
    { return m_ppic; }

    protected final State m_s;
    protected final String m_msg;
    protected final String m_pid;
    protected final String m_pdn;
    protected final String m_ppic;
}
