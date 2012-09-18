/*
 * Copyright 2008-2012 Xebia and the original author or authors.
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
package fr.xebia.catalina.authenticator;

import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.util.MD5Encoder;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Random;
import java.util.regex.Pattern;

/**
 * <p>
 * Form based Authenticator which does not require external login configuration (login-page and error-page).
 * </p>
 * <p/>
 * <p>Sample, of <code></code>context.xml</p>
 * <pre><code>
 * &lt;Context &gt;
 *     &lt;Valve className="fr.xebia.catalina.authenticator.XFormAuthenticator" /&gt;
 * &lt;/Context&gt;
 * </code>
 * </pre>
 *
 * @author <a href="mailto:cleclerc@xebia.fr">Cyrille Le Clerc</a>
 */
public class XFormAuthenticator extends ValveBase {

    private static Log log = LogFactory.getLog(XFormAuthenticator.class);

    private final static String FORM_REDIRECT_URL = "j_redirect_url";

    /**
     * name of the username cookie
     */
    private final static String USERNAME_COOKIE = "___username";

    /**
     * name of the hash cookie
     */
    private final static String HASH_COOKIE = "___hash";

    private Pattern includeUrlPatternRegex = null;

    private String excludeUrlPattern;

    private Pattern excludeUrlPatternRegex = Pattern.compile(".*\\.ico" +
            "|" + ".*\\.png|.*\\.jpg|.*\\.jpeg|.*\\.bmp|.*\\.gif" +
            "|" + ".*\\.css" +
            "|" + ".*\\.js");

    private String secret = String.valueOf(new Random().nextLong());

    public boolean isSkipAuthenticationRequest(Request request) {

        // like "" for root context or "/foo" for "foo" context
        String requestURI = request.getDecodedRequestURI();
        String contextPath = request.getContextPath();

        if (!requestURI.startsWith(contextPath)) {
            log.warn("Unexpected URI '" + requestURI + "' for contextPath='" + contextPath + "'");
            return false;
        }
        String contextRelativePath = requestURI.substring(contextPath.length());

        if (excludeUrlPatternRegex == null) {
            log.trace("No excludeUrlPatternRegex defined");
        } else if (excludeUrlPatternRegex.matcher(contextRelativePath).matches()) {
            if (log.isTraceEnabled())
                log.trace("Skip authentication for requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', match excludeUrlPatternRegex='" + excludeUrlPatternRegex + "'");
            return true;
        } else {
            if (log.isTraceEnabled())
                log.trace("Don't match excludeUrlPatternRegex: requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', match excludeUrlPatternRegex='" + excludeUrlPatternRegex + "'");
        }

        if (includeUrlPatternRegex == null) {
            log.debug("No includeUrlPatternRegex defined");
        } else if (!includeUrlPatternRegex.matcher(contextRelativePath).matches()) {
            if (log.isTraceEnabled())
                log.trace("Skip authentication for requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', do NOT match includeUrlPatternRegex='" + includeUrlPatternRegex + "'");
            return true;
        } else {
            if (log.isTraceEnabled())
                log.trace("Match includeUrlPatternRegex: requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', match excludeUrlPatternRegex='" + excludeUrlPatternRegex + "'");
        }

        if (log.isTraceEnabled())
            log.trace("No exclude pattern for requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "'");
        return false;
    }

    /**
     * @return authenticated user or <code>null</code> if user is not authenticated.
     */
    protected Principal authenticate(Request request, Response response) throws IOException {
        final String username = getCookieValue(USERNAME_COOKIE, request);
        String actualHash = getCookieValue(HASH_COOKIE, request);


        if (username == null || username.isEmpty()) {
            return null;
        }

        String expectedHash = hash(username, this.secret);

        if (!expectedHash.equals(actualHash)) {
            log.warn("Authentication FAILURE - Invalid hash for username:'" + username +
                    "', ip:'" + request.getRemoteAddr() + "', request: '" + request.getRequestURL() + "'");

            log.warn("NOTE: If your application is clusterized on several nodes, ensure the 'secret' attribute is defined on the Valve's configuration");

            response.addCookie(new Cookie(USERNAME_COOKIE, null));
            response.addCookie(new Cookie(HASH_COOKIE, null));
            return null;
        }
        return new Principal() {
            public String getName() {
                return username;
            }

            @Override
            public String toString() {
                return "principal['" + getName() + "']";
            }
        };
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        String requestURI = request.getDecodedRequestURI();
        String contextPath = request.getContextPath();

        Principal principal = authenticate(request, response);

        if (principal != null) {
            if (log.isDebugEnabled())
                log.debug("Authorize request " + request.getRequestURL() + " for " + principal);

            getNext().invoke(request, response);
            return;
        }

        boolean isAuthenticationRequest = requestURI.startsWith(contextPath) &&
                requestURI.endsWith(Constants.FORM_ACTION);
        if (isAuthenticationRequest) {
            String method = request.getMethod();
            String username = request.getParameter(Constants.FORM_USERNAME);
            String password = request.getParameter(Constants.FORM_PASSWORD);
            String redirectUrl = request.getParameter(FORM_REDIRECT_URL);

            // TODO check method = POST
            Principal user = getContainer().getRealm().authenticate(username, password);

            if (user == null) {
                // auth failure
                if (log.isInfoEnabled())
                    log.info("Authentication FAILURE for '" + username + "' from " + request.getRemoteAddr());

                forwardToErrorPage(request, response);
            } else {
                if (log.isInfoEnabled())
                    log.info("Authentication SUCCESS for '" + username + "' from " + request.getRemoteAddr() + " redirect to '" + redirectUrl + "'");

                encodeCookie(response, user);
                response.sendRedirect(redirectUrl);
            }
            return;
        }

        boolean isSkipAuthenticationUrl = isSkipAuthenticationRequest(request);
        if (isSkipAuthenticationUrl) {
            if (log.isDebugEnabled())
                log.debug("Skip authentication for request " + request.getRequestURL());
            getNext().invoke(request, response);
            return;
        }

        String redirectUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();
        if (queryString != null && !queryString.isEmpty()) {
            redirectUrl += "?" + request.getQueryString();
        }
        if (log.isDebugEnabled())
            log.debug("Redirect to authentication page request " + redirectUrl);

        forwardToLoginPage(request, response, redirectUrl);
    }

    protected static MessageDigest md5Digester;

    private MD5Encoder md5Encoder = new MD5Encoder();

    public XFormAuthenticator() {
        try {
            md5Digester = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    protected String hash(String principal, String salt) {
        byte[] md5;
        synchronized (md5Digester) {
            md5 = md5Digester.digest(new String(salt + ":" + principal).getBytes());
        }

        return md5Encoder.encode(md5);
    }

    private void encodeCookie(Response response, Principal principal) throws IOException {
        String hash = hash(principal.getName(), this.secret);
        response.addCookie(new Cookie(USERNAME_COOKIE, principal.getName()));
        response.addCookie(new Cookie(HASH_COOKIE, hash));
    }

    /**
     * @return cookie value or <code>null</code> if not found
     */
    protected String getCookieValue(String name, Request request) throws IOException {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || name == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }


    protected void forwardToErrorPage(Request request, Response response) throws IOException {
        HttpServletResponse httpServletResponse = response.getResponse();
        httpServletResponse.setContentType("text/html");
        httpServletResponse.addHeader("x-error", "authentication-error");
        PrintWriter writer = httpServletResponse.getWriter();
        writer.println("<html>");
        writer.println("  <head>");
        writer.println("    <title>Authentication Error</title>");
        writer.println("  </head>");
        writer.println("  <body>");
        writer.println("    <div>Authentication Error</div>");
        writer.println("  </body>");
        writer.println("</html>");
        writer.flush();
    }

    protected void forwardToLoginPage(Request request, Response response, String redirectUrl) throws IOException {
        HttpServletResponse httpServletResponse = response.getResponse();
        httpServletResponse.setContentType("text/html");

        httpServletResponse.addHeader("X-Robots-Tag", "noindex, nofollow");
        PrintWriter writer = httpServletResponse.getWriter();
        writer.println("<html>");
        writer.println("  <head>");
        writer.println("    <title>Private Application - Authentication</title>");
        writer.println("    <meta name='robots' content='noindex, nofollow'>");
        writer.println("  </head>");
        writer.println("  <body>");
        writer.println("    <h1>Private Application - Authentication</h1>");
        writer.println("    <form action='" + request.getContextPath() + Constants.FORM_ACTION + "' method='post'>");
        writer.println("      <input name='" + FORM_REDIRECT_URL + "' value='" + redirectUrl + "' type='hidden'>");
        writer.println("      <fieldset>");
        writer.println("        <div>");
        writer.println("          <label for='" + Constants.FORM_USERNAME + "'>Username</label>");
        writer.println("          <input id='" + Constants.FORM_USERNAME + "'  name='" + Constants.FORM_USERNAME + "' type='text'/>");
        writer.println("        </div>");
        writer.println("        <div>");
        writer.println("          <label for='" + Constants.FORM_PASSWORD + "'>Password</label>");
        writer.println("          <input id='" + Constants.FORM_PASSWORD + "' name='" + Constants.FORM_PASSWORD + "' type='password'/>");
        writer.println("        </div>");
        writer.println("        <div>");
        writer.println("          <button type='submit'>Login</input>");
        writer.println("        </div>");
        writer.println("      </fieldset>");
        writer.println("    </form>");
        writer.println("  </body>");
        writer.println("</html>");
        writer.flush();

    }

    public void setIncludeUrlPattern(String includeUrlPattern) {
        log.debug("setIncludeUrlPattern(" + includeUrlPattern + ")");
        this.includeUrlPatternRegex = Pattern.compile(includeUrlPattern);
    }

    public void setExcludeUrlPattern(String excludeUrlPattern) {
        log.debug("setExcludeUrlPattern(" + excludeUrlPattern + ")");
        this.excludeUrlPatternRegex = Pattern.compile(excludeUrlPattern);
    }

    public void setSecret(String secret) {
        log.debug("setSecret(xxx)");
        this.secret = secret;
    }
}
