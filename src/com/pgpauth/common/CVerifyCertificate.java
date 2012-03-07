package com.pgpauth.common;

// Given an input stream that purports to contain a master+subkey set
// of PGPkeys, return any interesting information after doing some basic
// checks on the keys.

import com.pgpauth.provider.AProvider;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;


import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.Text;
import com.google.appengine.api.datastore.Query;

import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.io.Serializable;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;

public class CVerifyCertificate
{

    // We assume that all relevant checks have been
    // done. This method overwrites any prior certificates
    // and indexs the certificate by email and fingerprint.
    public static void storeInfo(Info info)
    {
        // 1) Add the base entity, keyed by fingerprint.
        Key k = keyFromFingerprint(info.getFingerprint());
        Entity ke = new Entity(k);
        ke.setUnindexedProperty(CDATA, new Text(info.getCertificateData()));
        ke.setUnindexedProperty(TS, info.getVerifyTimestamp());
        String ppic = info.getProfileImage();
        if (!Utils.isEmpty(ppic)) {
            ke.setUnindexedProperty(PPIC, ppic);
        }
        String pdn = info.getProviderDisplayName(false);
        if (!Utils.isEmpty(pdn)) {
            ke.setUnindexedProperty(PDN, pdn);
        }
        k = Db.store(ke);

        // 2) Add an indexing key to let us search by type/pid
        // The key format is:
        // type::providerid::fingerprint

        Key emkey = indexKeyFor(info);
        Db.store(new Entity(emkey));

        // 3) Finally, save Info in memcache.
        Utils.storeMemCache
            (Utils.NS.CERT, info.getFingerprint(), info, 300*1000);
    }

    private final static Key indexKeyFor(Info info)
    {
        CUserID id = info.getID();
        return
            new KeyFactory.Builder
            (DOMAIN, id.getType())
            .addChild(PID, id.getProviderID())
            .addChild(EFP, info.getFingerprint())
            .getKey();
    }

    private final static Key keyFromFingerprint(String fp)
    {
        if (Utils.isEmpty(fp)) {
            return null;
        }

        int len = fp.length();
        if (len < 8) {
            return null;
        }
        fp = fp.toLowerCase();

        long keyid = (new BigInteger(fp.substring(len-8), 16)).longValue();
        return (new KeyFactory.Builder(KEYID, keyid)
                .addChild(FP, fp)
                .getKey());
    }

    public static Info lookupByFingerprint(String fp)
    {
        if (fp == null) {
            return null;
        }
        // 0) Canonical fp
        fp = fp.toLowerCase();

        // 1) First check memcache.
        Info ret = (Info) (Utils.fetchMemCache(Utils.NS.CERT, fp));
        if (ret != null) { return ret; }

        // 2) Check db
        Key k = keyFromFingerprint(fp);
        Entity ke = Db.find(k);
        if (ke == null) { return null; }

        ret =
            getInfo
            (((Text)(ke.getProperty(CDATA))).getValue(), false);

        if (ret != null) {
            // add misc properties.
            ret.setVerifyTimestamp((long)(ke.getProperty(TS)));
            String ppic = (String)(ke.getProperty(PPIC));
            if (!Utils.isEmpty(ppic)) {
                ret.setProfileImage(ppic);
            }
            String pdn = (String)(ke.getProperty(PDN));
            if (!Utils.isEmpty(pdn)) {
                ret.setProviderDisplayName(pdn);
            }
            Utils.storeMemCache
                (Utils.NS.CERT, ret.getFingerprint(), ret, 300*1000);
        }
        return ret;        
    }

    public static List<String> lookupByKeyID(long l)
    {
        List<String> ret = new ArrayList<String>();

        // run a parent query
        Key qk = KeyFactory.createKey(KEYID, l);
        Query q = new Query(qk).setKeysOnly();
        Iterator<Entity> qri = Db.query(q);
        if (qri != null) { 
            while (qri.hasNext()) {
                Entity qe = qri.next();
                ret.add(qe.getKey().getName());
            }
        }
        return ret;
    }

    public static List<String> lookupByID(CUserID id)
    {
        List<String> ret = new ArrayList<String>();

        // run a parent query
        Key qk = new KeyFactory.Builder(DOMAIN, id.getType())
            .addChild(PID, id.getProviderID())
            .getKey();

        Query q = new Query(qk).setKeysOnly();
        Iterator<Entity> qri = Db.query(q);
        if (qri != null) { 
            while (qri.hasNext()) {
                Entity qe = qri.next();
                ret.add(qe.getKey().getName());
            }
        }
        return ret;
    }

    public static void removeInfo(Info info)
    {
        Utils.removeMemCache(Utils.NS.CERT, info.getFingerprint());

        Key k = keyFromFingerprint(info.getFingerprint());
        Db.remove(k);

        // Also remove the indexing key.
        Key emkey = indexKeyFor(info);
        Db.remove(emkey);
    }

    public static Info getInfo(String data, boolean check)
        throws BadException
    {
        try { return _getInfo(data, check); }
        catch (RuntimeException rex) {
            throw rex;
        }
        catch (Exception ex) {
            throw new BadException(ex);
        }
    }

    @SuppressWarnings("unchecked")
    private static Info _getInfo(String data, boolean check)
        throws IOException, PGPException, SignatureException
    {
        PGPPublicKeyRingCollection pkrc =
            new PGPPublicKeyRingCollection
            (PGPUtil.getDecoderStream
             (new ByteArrayInputStream
              (data.getBytes("utf-8"))));

        PGPPublicKeyRing pkr = getExactlyOne
            ((Iterator<PGPPublicKeyRing>)pkrc.getKeyRings(),
             "public key", null);

        PGPPublicKey master = getExactlyOne
            ((Iterator<PGPPublicKey>)pkr.getPublicKeys(),
             "master key", new Sel<PGPPublicKey>() {
                public boolean select(PGPPublicKey item)
                { return item.isMasterKey(); }
            });

        String uid = getExactlyOne
            ((Iterator<String>)master.getUserIDs(), "user id", null);

        Info ret = makeInfo(uid, data, Utils.byte2str(master.getFingerprint()));
        if (check) {
            verifyKeys(pkr, master, uid);
        }
        return ret;
    }

    // Ensure that the master key is self-signed, and each subkey
    // has a binding signature from the master.
    @SuppressWarnings("unchecked")
    private final static void verifyKeys
        (PGPPublicKeyRing pkr, PGPPublicKey master, String uid)
        throws BadException,PGPException,SignatureException
    {
        boolean masterok = false;
        for (Iterator<PGPPublicKey> pki = pkr.getPublicKeys();
             pki.hasNext();) {
            PGPPublicKey cur = pki.next();
            if (cur.isMasterKey()) {
                if (cur != master) {
                    throw new BadException("Unexpected dup master");
                }
                checkMasterKey(master, uid);
                masterok = true;
            }
            else {
                checkSubKey(cur, master);
            }
        }
        if (!masterok) {
            throw new BadException("Unexpected missing master check");
        }
    }

    @SuppressWarnings("unchecked")
    private final static void checkSubKey
        (PGPPublicKey subkey, PGPPublicKey master)
        throws BadException,PGPException,SignatureException
    {
        Iterator<PGPSignature> sigs = (Iterator<PGPSignature>)
            subkey.getSignaturesOfType
            (PGPSignature.SUBKEY_BINDING);
        if (sigs == null) {
            throw new BadException
                ("Subkey in certificate is missing a binding signature");
        }
        boolean ok = false;
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            if (sig.getKeyID() != master.getKeyID()) { continue; }
            sig.init(s_provider, master);
            ok = sig.verifyCertification(master, subkey);
            if (!ok) {
                throw new BadException("Subkey signature incorrect");
            }
        }
        if (!ok) {
            throw new BadException("Missing a binding signature for subkey");
        }
    }

    @SuppressWarnings("unchecked")
    private final static void checkMasterKey(PGPPublicKey master, String uid)
        throws BadException,PGPException,SignatureException
    {
        long vs = master.getValidSeconds();
        if (vs != 0) {
            long expire = master.getCreationTime().getTime()+(vs*1000);
            long now = System.currentTimeMillis();
            if (expire < now) {
                throw new BadException
                    ("Sorry, this certificate expired on "+new Date(expire));
            }
        }

        boolean ok = false;
        Iterator<PGPSignature> sigs = master.getSignaturesForID(uid);
        if (sigs != null) {
            while (sigs.hasNext()) {
                PGPSignature sig = sigs.next();
                if (sig.getKeyID() != master.getKeyID()) {
                    // not interested in this signature.
                    continue;
                }
                sig.init(s_provider, master);
                ok = sig.verifyCertification(uid, master);
                if (!ok) {
                    throw new BadException("incorrect master self-signature");
                }
            }
        }
        if (!ok) {
            throw new BadException("Missing master self-signature");
        }
    }


    private final static Info makeInfo
        (final String uid, final String orig, final String fp)
        throws BadException
    {
        CUserID id = AProvider.fromString(uid);
        if (id == null) {
            throw new NotHandledException(uid);
        }
        return new Info(id, null, orig, fp);
    }

    // Pluck exactly one item from this iterator, with an optional selector
    // to filter results.
    private final static <T> T getExactlyOne
        (Iterator<T> iterator, String msg, Sel<T> sel)
        throws BadException
    {
        if (iterator == null) {
            throw new BadException("Missing "+msg);
        }
        T ret = null;
        while (iterator.hasNext()) {
            T cur = iterator.next();
            if ((sel != null) && !sel.select(cur)) { continue; }

            if (ret == null) { ret = cur; }
            else {
                throw new BadException
                    ("Expected to find exactly one "+msg+", but found more");
            }
        }
        if (ret == null) {
            throw new BadException("Missing "+msg);
        }
        return ret;
    }

    private interface Sel<T>
    { public boolean select(T item); }

    @SuppressWarnings("serial")
    public static class BadException
        extends RuntimeException
    {
        public BadException(String msg, Throwable cause)
        { super(msg, cause); }
        public BadException(Throwable cause)
        { super(cause); }
        public BadException(String msg)
        { super(msg); }
    }

    @SuppressWarnings("serial")
    public static class NotHandledException
        extends BadException
    {
        public NotHandledException(String msg)
        { super(msg); }
    }

    public static class Info
        implements Serializable
    {
        static final long serialVersionUID = -933679989624637282L;

        private Info
            (CUserID uid, String providername, String orig, String fp)
        {
            m_uid = uid;
            m_origcert = orig;
            m_fp = fp;
            m_vts = -1;
        }

        public String getProviderDisplayName(boolean fake)
        {
            if (m_pdn != null) { return m_pdn; }
            if (!fake) { return null; }

            return m_uid.getProfileLinkName();
        }

        public void setProviderDisplayName(String s)
        { m_pdn = s; }
        public long getVerifyTimestamp()
        { return m_vts; }
        public void setVerifyTimestamp(long v)
        { m_vts = v; }
        public String getProfileImage()
        { return m_ppic; }
        public void setProfileImage(String p)
        { m_ppic = p; }
        public CUserID getID()
        { return m_uid; }
        public String getFingerprint()
        { return m_fp; }
        public String getCertificateData()
        { return m_origcert; }
        private final CUserID m_uid;
        private final String m_origcert;
        private final String m_fp;
        private String m_ppic;
        private String m_pdn;
        private long m_vts;
    }

    private final static BcPGPContentVerifierBuilderProvider s_provider =
        new BcPGPContentVerifierBuilderProvider();

    private final static String FP = "fp";
    private final static String KEYID = "kid";
    private final static String CDATA = "crt";
    private final static String TS = "ts";
    private final static String PPIC = "ppic";
    private final static String PDN = "pdn";
    private final static String EFP = "efp";
    private final static String DOMAIN = "d";
    private final static String PID = "pid";
}
