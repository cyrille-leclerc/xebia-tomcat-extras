/*
 * Copyright 2009-2010 Xebia and the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.xebia.catalina.listener;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * <p>
 * Tomcat {@link LifecycleListener} to bypass/disable all SSL verifications on standard
 * {@link HttpsURLConnection} at Tomcat startup.
 * </p>
 * <p>
 * Accepted SSL communications include :
 * </p>
 * <ul>
 * <li>Self-signed certificates,</li>
 * <li>Non trusted certificate authorities,</li>
 * <li>Expired certificates,</li>
 * <li>Mismatch between the HTTP <code>Host</code> and the certificate's Common Name (CN).</li>
 * </ul>
 * 
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class AcceptAllSslCertificatesListener implements LifecycleListener {

    /**
     * This {@link HostnameVerifier} allows SSL HTTPS requests with hostname that does not match the server
     * SSL certificate CN.
     */
    protected static class AcceptAllHostnameVerifier implements HostnameVerifier {

        private HostnameVerifier initialHostnameVerifier;

        public AcceptAllHostnameVerifier(HostnameVerifier initialHostnameVerifier) {
            super();
            this.initialHostnameVerifier = initialHostnameVerifier;
        }

        /**
         * {@inheritDoc}
         */
        public boolean verify(String hostname, SSLSession session) {
            if (initialHostnameVerifier.verify(hostname, session)) {
                if (log.isDebugEnabled()) {
                    log.debug("Matching hostname : " + buildSslSessionLogMessage(hostname, session));
                }
            } else {
                log.warn("SSL SECURITY IS COMPROMISED ! Disabled SSL hostname verification for mismatch : "
                         + buildSslSessionLogMessage(hostname, session));
            }
            return true;
        }

        private String buildSslSessionLogMessage(String hostname, SSLSession session) {
            String msg = "given hostname=" + hostname + ", sslSession[peer=" + session.getPeerHost() + ":"
                         + session.getPeerPort() + ", peerPrincipal=[";
            try {
                msg += session.getPeerPrincipal();
            } catch (SSLPeerUnverifiedException e) {
                msg += e.toString();
            }
            msg += "]]";
            return msg;
        }
    }

    /**
     * <p>
     * This {@link X509TrustManager} allows :
     * </p>
     * <ul>
     * <li>Self-signed certificates,</li>
     * <li>Non trusted certificate authorities,</li>
     * <li>Expired certificates.</li>
     * </ul>
     */
    protected static class AcceptAllX509TrustManager implements X509TrustManager {

        private final X509TrustManager x509TrustManager;

        public AcceptAllX509TrustManager() throws GeneralSecurityException {
            this(null);
        }

        /**
         * @param x509TrustManager the X509 Trust Manager to test the given certificates chain for log
         *            messages purpose. If <code>null</code>, the JVM default X509 Trust Manager is used.
         */
        public AcceptAllX509TrustManager(X509TrustManager x509TrustManager) throws GeneralSecurityException {
            super();
            if (x509TrustManager == null) {
                this.x509TrustManager = getDefaultX509TrustManager();
            } else {
                this.x509TrustManager = x509TrustManager;
            }
        }

        /**
         * {@inheritDoc}
         */
        public void checkClientTrusted(X509Certificate[] certs, String authType) {
            try {
                x509TrustManager.checkClientTrusted(certs, authType);
            } catch (CertificateException e) {
                if (log.isTraceEnabled()) {
                    log.error(buildLogCertificationException(certs), e);
                } else {
                    log.error(buildLogCertificationException(certs) + " : " + e);
                }
            }
        }

        /**
         * {@inheritDoc}
         */
        public void checkServerTrusted(X509Certificate[] certs, String authType) {
            try {
                x509TrustManager.checkServerTrusted(certs, authType);
            } catch (CertificateException e) {
                if (log.isTraceEnabled()) {
                    log.error(buildLogCertificationException(certs), e);
                } else {
                    log.error(buildLogCertificationException(certs) + " : " + e);
                }
            }
        }

        /**
         * {@inheritDoc}
         */
        public X509Certificate[] getAcceptedIssuers() {
            return x509TrustManager.getAcceptedIssuers();
        }

        /**
         * Returns the first default X509 Trust Manager associated with default algorithm
         * 
         * @see TrustManagerFactory#getDefaultAlgorithm()
         * @see TrustManagerFactory#getTrustManagers()
         */
        protected X509TrustManager getDefaultX509TrustManager() throws GeneralSecurityException {
            // load default trust managers
            String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(defaultAlgorithm);
            trustManagerFactory.init((KeyStore)null);
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    return (X509TrustManager)trustManager;
                }
            }
            throw new IllegalStateException("No X509 Trust Manager found");
        }

        /**
         * Builds a log message describing the given <code>certs</code> chain.
         */
        private String buildLogCertificationException(X509Certificate[] certs) {
            StringBuilder sb = new StringBuilder("Non blocking X509 Certificate exception - ");

            if (certs.length == 1) {
                X509Certificate certificate = certs[0];

                String validityError;
                String validityInterval;
                try {
                    certificate.checkValidity();
                    validityError = "";
                    validityInterval = "";
                } catch (CertificateNotYetValidException cnyve) {
                    validityError = "not-yet-valid ";
                    validityInterval = " (valid from " + certificate.getNotBefore() + " until "
                                       + certificate.getNotAfter() + ")";
                } catch (CertificateExpiredException cee) {
                    validityError = "expired ";
                    validityInterval = " (valid from " + certificate.getNotBefore() + " until "
                                       + certificate.getNotAfter() + ")";
                }

                if (certificate.getSubjectDN().equals(certificate.getIssuerDN())) {
                    sb.append("Untrusted self-signed " + validityError + "certificate: '"
                              + certificate.getSubjectDN() + "'" + validityInterval);
                } else {
                    sb.append("Untrusted " + validityError + "certificate: '" + certificate.getSubjectDN()
                              + "' issued by '" + certificate.getIssuerDN() + "'" + validityInterval);
                }
            } else {
                sb.append("Untrusted certificates chain: ");
                for (int i = 0; i < certs.length; i++) {
                    X509Certificate certificate = certs[i];
                    if (i > 0) {
                        sb.append(", ");
                    }

                    String validityError;
                    String validityInterval;
                    try {
                        certificate.checkValidity();
                        validityError = "";
                        validityInterval = "";
                    } catch (CertificateNotYetValidException cnyve) {
                        validityError = "not-yet-valid ";
                        validityInterval = " (valid from " + certificate.getNotBefore() + " until "
                                           + certificate.getNotAfter() + ")";
                    } catch (CertificateExpiredException cee) {
                        validityError = "expired ";
                        validityInterval = " (valid from " + certificate.getNotBefore() + " until "
                                           + certificate.getNotAfter() + ")";
                    }
                    if (certificate.getSubjectDN().equals(certificate.getIssuerDN())) {
                        sb.append("self-signed " + validityError + "certificate '"
                                  + certificate.getSubjectDN() + "'" + validityInterval);
                    } else {
                        sb.append("" + validityError + "certificate '" + certificate.getSubjectDN()
                                  + "' issued by '" + certificate.getIssuerDN() + "'" + validityInterval);
                    }
                }
            }
            return sb.toString();
        }
    };

    private static Log log = LogFactory.getLog(AcceptAllSslCertificatesListener.class);

    private boolean enabled = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void lifecycleEvent(LifecycleEvent event) {
        if (Lifecycle.BEFORE_START_EVENT.equals(event.getType())) {
            if (enabled) {
                // HOST NAME VERIFIER
                HostnameVerifier initialHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                HttpsURLConnection
                    .setDefaultHostnameVerifier(new AcceptAllHostnameVerifier(initialHostnameVerifier));

                // X509 CERTIFICATE VERIFIER
                SSLSocketFactory sslSocketFactory;
                try {
                    SSLContext sslContext = SSLContext.getInstance("SSL");
                    TrustManager[] acceptAllCertificatesTrustManagers = new TrustManager[] {
                        new AcceptAllX509TrustManager()
                    };
                    sslContext.init(null, acceptAllCertificatesTrustManagers, new SecureRandom());
                    sslSocketFactory = sslContext.getSocketFactory();
                } catch (GeneralSecurityException e) {
                    throw new RuntimeException("SSLSocketFactory initialization exception", e);
                }
                HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
                log.error("SSL VERIFICATIONS DISABLED ! SHOULD NOT BE USED IN PRODUCTION !");
            } else {
                log.info("SSL verifications NOT bypassed because listener is disabled");
            }
        }

    }

    public void setEnabled(boolean enabled) {
        if (this.enabled == true && enabled == false) {
            throw new UnsupportedOperationException(
                                                    "SSL verifications can NOT be re-enabled once they have been disabled");
        }
        this.enabled = enabled;
    }
}
