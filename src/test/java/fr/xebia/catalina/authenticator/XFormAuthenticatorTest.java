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

import static org.junit.Assert.*;
import org.apache.catalina.connector.Request;
import org.junit.Test;

/**
 * @author <a href="mailto:cleclerc@xebia.fr">Cyrille Le Clerc</a>
 */
public class XFormAuthenticatorTest {

    @Test
    public void skip_authentication_for_favicon(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/favicon.ico";
            }

            @Override
            public String getContextPath() {
                return "";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(true, actual);
    }

    @Test
    public void skip_authentication_for_css_in_root_context_path(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/css/my.css";
            }

            @Override
            public String getContextPath() {
                return "";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(true, actual);
    }

    @Test
    public void skip_authentication_for_css_in_sub_context_path(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/myapp/css/my.css";
            }

            @Override
            public String getContextPath() {
                return "/myapp";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(true, actual);
    }


    public void skip_authentication_for_img_png_in_root_context_path(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/img/my.png";
            }

            @Override
            public String getContextPath() {
                return "";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(true, actual);
    }

    @Test
    public void skip_authentication_for_img_png_in_sub_context_path(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/myapp/img/my.png";
            }

            @Override
            public String getContextPath() {
                return "/myapp";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(true, actual);
    }

    public void dont_skip_authentication_for_jsp_in_root_context(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/home.jsp";
            }

            @Override
            public String getContextPath() {
                return "";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(false, actual);
    }

    @Test
    public void dont_skip_authentication_for_jsp_in_sub_context(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/myapp/home.jsp";
            }

            @Override
            public String getContextPath() {
                return "/myapp";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(false, actual);
    }

    public void dont_skip_authentication_for_servlet_in_root_context(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/home";
            }

            @Override
            public String getContextPath() {
                return "";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(false, actual);
    }

    @Test
    public void dont_skip_authentication_for_servlet_in_sub_context(){
        XFormAuthenticator formAuthenticator = new XFormAuthenticator();
        Request request = new Request(){
            @Override
            public String getDecodedRequestURI() {
                return "/myapp/home";
            }

            @Override
            public String getContextPath() {
                return "/myapp";
            }
        };

        boolean actual = formAuthenticator.isSkipAuthenticationRequest(request);
        assertEquals(false, actual);
    }
}
