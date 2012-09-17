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

import org.apache.catalina.Authenticator;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
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
public class XFormAuthenticator extends FormAuthenticator implements Authenticator {

    private static Log log = LogFactory.getLog(XFormAuthenticator.class);

    private Pattern includeUrlPattern = null;

    private Pattern excludeUrlPattern = Pattern.compile(".*\\.ico" +
            "|" + ".*\\.png|.*\\.jpg|.*\\.jpeg|.*\\.bmp|.*\\.gif" +
            "|" + ".*\\.css" +
            "|" + ".*\\.js");

    public XFormAuthenticator() {
        super();
        setChangeSessionIdOnAuthentication(false);
    }

    public boolean skipAuthentication(Request request) {
        // like "" for root context or "/foo" for "foo" context
        String requestURI = request.getDecodedRequestURI();
        String contextPath = request.getContextPath();

        if (!requestURI.startsWith(contextPath)) {
            log.warn("Unexpected URI '" + requestURI + "' for contextPath='" + contextPath + "'");
            return false;
        }
        String contextRelativePath = requestURI.substring(contextPath.length());

        if (excludeUrlPattern == null) {
            log.debug("No excludeUrlPattern defined");
        } else if (excludeUrlPattern.matcher(contextRelativePath).matches()) {
            if (log.isDebugEnabled())
                log.debug("Skip authentication for requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', match excludeUrlPattern='" + excludeUrlPattern + "'");
            return true;
        } else {
            if (log.isDebugEnabled())
                log.debug("Don't match excludeUrlPattern: requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', match excludeUrlPattern='" + excludeUrlPattern + "'");
        }

        if (includeUrlPattern == null) {
            log.debug("No includeUrlPattern defined");
        } else if (!includeUrlPattern.matcher(contextRelativePath).matches()) {
            if (log.isDebugEnabled())
                log.debug("Skip authentication for requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', do NOT match includeUrlPattern='" + includeUrlPattern + "'");
            return true;
        } else {
            if (log.isDebugEnabled())
                log.debug("Match includeUrlPattern: requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "', match excludeUrlPattern='" + excludeUrlPattern + "'");
        }

        if (log.isDebugEnabled())
            log.debug("Perform authentication for requestUri='" + requestURI + "', contextRelativePath='" + contextRelativePath + "'");
        return false;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        boolean skipAuthentication = skipAuthentication(request);

        if (skipAuthentication) {
            getNext().invoke(request, response);
        } else {
            super.invoke(request, response);
        }
    }

    @Override
    protected void forwardToErrorPage(Request request, Response response, LoginConfig config) throws IOException {
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

    @Override
    protected void forwardToLoginPage(Request request, Response response, LoginConfig config) throws IOException {
        HttpServletResponse httpServletResponse = response.getResponse();
        httpServletResponse.setContentType("text/html");

        httpServletResponse.addHeader("X-Robots-Tag", "noindex, nofollow");
        PrintWriter writer = httpServletResponse.getWriter();
        writer.println("<html>");
        writer.println("  <head>");
        writer.println("    <title>Authentication</title>");
        writer.println("    <meta name='robots' content='noindex, nofollow'>");
        writer.println("  </head>");
        writer.println("  <body>");
        writer.println("    <h1>Authentication Form</h1>");
        writer.println("    <form action='" + request.getContextPath() + Constants.FORM_ACTION + "' method='post'>");
        writer.println("      <fieldset>");
        writer.println("        <div>");
        writer.println("          <label for='" + Constants.FORM_USERNAME + "'>Username</label>");
        writer.println("          <input name='" + Constants.FORM_USERNAME + "' type='text'/>");
        writer.println("        </div>");
        writer.println("        <div>");
        writer.println("          <label for='" + Constants.FORM_PASSWORD + "'>Password</label>");
        writer.println("          <input name='" + Constants.FORM_PASSWORD + "' type='password'/>");
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

    public String getIncludeUrlPattern() {
        return includeUrlPattern.pattern();
    }

    public void setIncludeUrlPattern(String includeUrlPattern) {
        this.includeUrlPattern = Pattern.compile(includeUrlPattern);
    }

    public String getExcludeUrlPattern() {
        return excludeUrlPattern.pattern();
    }

    public void setExcludeUrlPattern(String excludeUrlPattern) {
        this.excludeUrlPattern = Pattern.compile(excludeUrlPattern);
    }

}
