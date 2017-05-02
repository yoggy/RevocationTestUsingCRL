//
// RevocationTestUsingCRL.java
//
// github:
//     https://github.com/yoggy/RevocationTestUsingCRL
//
// license:
//     Copyright (c) 2017 yoggy <yoggy0@gmail.com>
//     Released under the MIT license
//     http://opensource.org/licenses/mit-license.php;//
//

package net.sabamiso.android.revocationtest.crl;

import android.util.Log;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

public class RevocationTestUsingCRL {
    public static final String TAG = RevocationTestUsingCRL.class.getSimpleName();

    protected static HashMap<String, Boolean> revocation_map = new HashMap<String, Boolean>();

    String target_url_str;

    public RevocationTestUsingCRL(String url_str) {
        target_url_str = url_str;
    }

    public boolean isRevoked() throws RevocationTestException {
        return isRevoked(target_url_str, true);
    }

    public static boolean isRevoked(String url_str, boolean use_cache) throws RevocationTestException {
        // URL normalization...
        String normalized_url_str = null;
        try {
            URL tmp = new URL(url_str);
            normalized_url_str = tmp.getProtocol() + "://" + tmp.getHost();
            if (tmp.getPort() != -1) {
                normalized_url_str += ":" + tmp.getPort();
            }
            normalized_url_str += "/";

        } catch (MalformedURLException e) {
            Log.e(TAG, "MalformedURLException", e);
            throw new RevocationTestException(e);
        }

        return isRevokedInner(normalized_url_str, use_cache);
    }

    static boolean isRevokedInner(String url_str, boolean use_cache) throws RevocationTestException {
        // cache
        if (revocation_map.containsKey(url_str) && use_cache == true) {
            boolean rv = revocation_map.get(url_str);
            if (rv) {
                Log.i(TAG, "Certificate is revoked! (cache)");
            }
            else {
                Log.i(TAG, "Certificate is not revoked. (cache)");
            }
            return rv;
        }

        HttpsURLConnection conn = null;
        URL url = null;
        try {
            url = new URL(url_str);
            conn = (HttpsURLConnection) url.openConnection();
            conn.connect();

            if (isRevoked(conn) == true) {
                Log.i(TAG, "Certificate is revoked!");
                revocation_map.put(url_str, true);
                return true;
            }
            final int status = conn.getResponseCode();
            Log.i(TAG, "response status code = " + status);
        } catch (FileNotFoundException e) {
            Log.e(TAG, "FileNotFoundException", e);
            Log.i(TAG, "body = " + readInputStreamAsString(conn.getErrorStream())); // 4xx, 5xxの時はgetErrorStream()を使う

            if (isRevoked(conn) == true) {
                Log.i(TAG, "Certificate is revoked!");
                revocation_map.put(url_str, true);
                return true;
            }
        } catch (MalformedURLException e) {
            Log.e(TAG, "MalformedURLException", e);
            throw new RevocationTestException(e);
        } catch (IOException e) {
            Log.e(TAG, "IOException", e);
            throw new RevocationTestException(e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }

        Log.i(TAG, "Certificate is not revoked.");
        revocation_map.put(url_str, false); // cache
        return false;
    }

    public static boolean isRevoked(HttpsURLConnection conn)  throws RevocationTestException {
        if (conn == null) {
            Log.e(TAG, "conn is null...");
            throw new RevocationTestException("conn is null...");
        }

        X509Certificate cert = getPeerX509Certificate(conn);
        if (cert == null) {
            throw new RevocationTestException("getPeerX509Certificate() failed...");
        }

        String crl_url = getCRLUrl(cert);
        Log.d(TAG, "crl_url=" + crl_url);
        if (crl_url == null) {
            throw new RevocationTestException("getCRLUrl() failed...");
        }

        X509CRL crl = getCRL(crl_url);
        boolean revoked = crl.isRevoked(cert);

        return revoked;
    }

    private static String readInputStreamAsString(InputStream is) {
        InputStreamReader isr = new InputStreamReader(is);
        StringBuilder sb = new StringBuilder();
        char [] buf = new char[2048];

        try {
            while(true) {
                int read_size = isr.read(buf);
                if (read_size < 0) break;
                sb.append(buf, 0, read_size);
            }
        } catch (IOException e) {
        }
        return sb.toString();
    }

    private static X509Certificate getPeerX509Certificate(HttpsURLConnection conn) {
        String peer_name = null;
        try {
            peer_name = conn.getPeerPrincipal().getName();
            Log.d(TAG, conn.getPeerPrincipal().toString());
        } catch (SSLPeerUnverifiedException e) {
            Log.e(TAG, "SSLPeerUnverifiedException", e);
            return null;
        }

        Certificate[] certs = null;
        try {
            certs = conn.getServerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            Log.e(TAG, "SSLPeerUnverifiedException", e);
            return null;
        }
        if (certs == null || certs.length < 2){
            Log.e(TAG, "invalid certs...");
            return null;
        }

        X509Certificate target_cert = null;
        X509Certificate[] x509certs = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; ++i) {
            x509certs[i] = (X509Certificate)certs[i];
            Log.d(TAG, "idx=" + i + ", subject:" + x509certs[i].getSubjectDN().getName());
            Log.d(TAG, "idx=" + i + ", issuer:" + x509certs[i].getIssuerDN().getName());
        }

        for (int i = 0; i < x509certs.length; ++i) {
            String dn = x509certs[i].getSubjectDN().getName();
            if (peer_name.equals(dn)) {
                target_cert = x509certs[i];
                break;
            }
        }

        if (target_cert == null) {
            Log.e(TAG, "cannot find target_cert...");
            return null;
        }

        return target_cert;
    }

    private static CRLDistPoint getCRLDistPoint(byte [] asn1_bytes) {
        if (asn1_bytes == null) return null;

        CRLDistPoint crldp = null;

        try {
            ASN1InputStream is1 = new ASN1InputStream(new ByteArrayInputStream(asn1_bytes));
            ASN1Primitive p1 = is1.readObject();
            if (p1 == null) return null;

            ASN1InputStream is2 = new ASN1InputStream(ASN1OctetString.getInstance(p1).getOctets());
            ASN1Primitive p2 = is2.readObject();
            if (p2 == null) return null;

            crldp = CRLDistPoint.getInstance(p2);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return crldp;
    }

    private static String getCRLUrl(X509Certificate cert) {
        byte[] asn1_bytes = cert.getExtensionValue("2.5.29.31"); // CRL Distribution Points OID:"2.5.29.31"
        if (asn1_bytes == null) {
            Log.e(TAG, "cannot find 2.5.29.31...");
            return null;
        }

        CRLDistPoint crldp = getCRLDistPoint(asn1_bytes);
        if (crldp == null) {
            Log.e(TAG, "cannot find CRLDistPoint...");
            return null;
        }

        String url = null;

        for(DistributionPoint dp : crldp.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            if (DistributionPointName.FULL_NAME != dpn.getType()) continue;
            GeneralNames gns = (GeneralNames)dpn.getName();
            for (GeneralName gn : gns.getNames()) {
                if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    continue;
                }
                DERIA5String der_str = DERIA5String.getInstance((ASN1TaggedObject)gn.toASN1Primitive(), false);
                url = der_str.getString();
                Log.d(TAG, "url=" + url);
            }
        }

        return url;
    }

    private static X509CRL getCRL(String crl_url) {
        HttpURLConnection conn = null;
        URL url = null;

        X509CRL crl = null;

        try {
            url = new URL(crl_url);
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoInput(true);
            conn.connect();

            final int status = conn.getResponseCode();
            Log.d(TAG, "response status code = " + status);

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            crl = (X509CRL) factory.generateCRL(conn.getInputStream());

        } catch (FileNotFoundException e) {
            Log.e(TAG, "FileNotFoundException", e);
            Log.i(TAG, "body = " + readInputStreamAsString(conn.getErrorStream())); // 4xx, 5xxの時はgetErrorStream()を使う
        } catch (MalformedURLException e) {
            Log.e(TAG, "MalformedURLException", e);
        } catch (IOException e) {
            Log.e(TAG, "IOException", e);
        } catch (CertificateException e) {
            Log.e(TAG, "CertificateException", e);
        } catch (CRLException e) {
            Log.e(TAG, "CRLException", e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }

        return crl;
    }
}
