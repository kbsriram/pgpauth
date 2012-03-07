package com.pgpauth.common;

/*
 * Encapsulate everything needed to complete a request
 */
import java.io.Serializable;
import java.net.URL;

public class CNonceOp
    implements Serializable
{
    static final long serialVersionUID = 5273043026625897700L;
    public enum Type { ADD, DEL };
    public CNonceOp
        (Type t, CVerifyCertificate.Info info, URL cburl, String cbstate)
    {
        m_type = t;
        m_info = info;
        m_nonce = Utils.makeNonce();
        m_id = Utils.makeNonce();
        m_cburl = cburl;
        m_cbstate = Utils.isEmpty(cbstate)?null:cbstate;
    }

    public Type getType()
    { return m_type; }
    public CVerifyCertificate.Info getInfo()
    { return m_info; }
    public String getNonce()
    { return m_nonce; }
    public String getId()
    { return m_id; }
    public URL getCbURL()
    { return m_cburl; }
    public String getCbState()
    { return m_cbstate; }
    public Serializable getExtra()
    { return m_extra; }
    public void setExtra(Serializable x)
    { m_extra = x; }

    private final String m_id;
    private final String m_nonce;
    private final URL m_cburl;
    private final String m_cbstate;
    private final Type m_type;
    private final CVerifyCertificate.Info m_info;
    private Serializable m_extra = null;
}
