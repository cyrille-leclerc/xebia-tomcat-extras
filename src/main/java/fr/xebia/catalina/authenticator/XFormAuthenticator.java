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
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author <a href="mailto:cleclerc@xebia.fr">Cyrille Le Clerc</a>
 */
public class XFormAuthenticator extends FormAuthenticator {

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
}
