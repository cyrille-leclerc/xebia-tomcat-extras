/*
 * Copyright 2002-2008 the original author or authors.
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
package org.apache.catalina.connector;

import java.io.IOException;

import javax.servlet.ServletException;

import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * <p>
 * Overwrite {@link Request#getRemoteAddr()} and {@link Request#getRemoteHost()} with the value of the incoming http header
 * <code>x-forwarded-for</code> if it exists. If {@link Request#getRemoteAddr()} and {@link Request#getRemoteHost()} are overwritten, their
 * initial values are respectively added in http headers <code>x-original-remote-addr</code> and <code>x-original-remote-host</code>.
 * </p>
 * <p> ServletRequest </p>
 * <p>
 * This valve must be located in the <code>org.apache.catalina.connector</code> package to get protected visibility on fields
 * {@link Request#remoteHost} and {@link Request#remoteAddr}.
 * </p>
 * 
 * @author <a href="mailto:cyrille.leclerc@pobox.com">Cyrille Le Clerc</a>
 */
public class XForwardedForAsRemoteHostValve extends ValveBase {

    private static final String X_FORWARDED_FOR_HEADER_NAME = "x-forwarded-for";

    protected static Log log = LogFactory.getLog(XForwardedForAsRemoteHostValve.class);
    
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        
        String xForwardedForHeader = request.getHeader(X_FORWARDED_FOR_HEADER_NAME);
        
        if (xForwardedForHeader != null && xForwardedForHeader.length() > 0) {
            
            String originalRemoteHost = request.getRemoteHost();
            request.getCoyoteRequest().getMimeHeaders().addValue("x-original-remote-host").setString(originalRemoteHost);
            request.remoteHost = xForwardedForHeader;
            
            String originalRemoteAddr = request.getRemoteAddr();
            request.getCoyoteRequest().getMimeHeaders().addValue("x-original-remote-addr").setString(originalRemoteAddr);
            request.remoteAddr = xForwardedForHeader;
            
            if (log.isDebugEnabled()) {
                log.debug("Overwrite remoteHost '" + originalRemoteHost + "' and 'originalRemoteAddr '" + originalRemoteAddr
                          + "' by header " + X_FORWARDED_FOR_HEADER_NAME + " '" + xForwardedForHeader + "'");
            }
        }
        
        getNext().invoke(request, response);
    }
    
}
