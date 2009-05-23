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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletException;

import org.apache.catalina.util.StringManager;
import org.apache.catalina.valves.Constants;
import org.apache.catalina.valves.ValveBase;

/**
 * <p>
 * Replaces the apparent client remote IP address and hostname for the request with the IP address list presented by a proxy or a load
 * balancer via a request headers.
 * </p>
 * <p>
 * Tomcat port of <a href="http://httpd.apache.org/docs/trunk/mod/mod_remoteip.html">mod_remoteip</a>.
 * </p>
 * <p>
 * TODO : add "remoteIpValve.syntax" NLSString.
 * </p>
 * 
 * @author <a href="mailto:cyrille.leclerc@pobox.com">Cyrille Le Clerc</a>
 */
public class RemoteIpValve extends ValveBase {
    
    private static final Pattern commaSeparatedPattern = Pattern.compile("\\s*,\\s*");
    
    /**
     * The descriptive information related to this implementation.
     */
    private static final String info = "org.apache.catalina.connector.RemoteIpValve/1.0";
    
    /**
     * The StringManager for this package.
     */
    protected static StringManager sm = StringManager.getManager(Constants.Package);
    
    protected static Pattern[] commaDelimitedListToPatternArray(String commaDelimitedPatterns) {
        String[] patterns = commaDelimitedListToStringArray(commaDelimitedPatterns);
        List<Pattern> patternsList = new ArrayList<Pattern>();
        for (String pattern : patterns) {
            try {
                patternsList.add(Pattern.compile(pattern));
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(sm.getString("remoteIpValve.syntax", pattern), e);
            }
        }
        return patternsList.toArray(new Pattern[0]);
    }
    
    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {
        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaSeparatedPattern
            .split(commaDelimitedStrings);
    }
    
    protected static String listToCommaDelimitedString(List<String> stringList) {
        if (stringList == null) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (Iterator<String> it = stringList.iterator(); it.hasNext();) {
            String element = it.next();
            if (element != null) {
                result.append(element);
                if (it.hasNext()) {
                    result.append(", ");
                }
            }
        }
        return result.toString();
    }
    
    private Pattern[] allowedInternalProxies = new Pattern[0];
    
    private String remoteIPHeader = "X-Forwarded-For";
    
    private String remoteIPProxiesHeader = "X-Forwarded-By";
    
    private Pattern[] trustedProxies = new Pattern[0];
    
    /**
     * Return descriptive information about this Valve implementation.
     */
    public String getInfo() {
        return info;
    }
    
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        final String originalRemoteAddr = request.getRemoteAddr();
        final String originalRemoteHost = request.getRemoteHost();
        
        if (matchesOne(originalRemoteAddr, allowedInternalProxies)) {
            String remoteIp = null;
            // In java 6, remoteIpProxiesHeaderValue will be declared as a java.util.deque
            LinkedList<String> remoteIpProxiesHeaderValue = new LinkedList<String>();
            LinkedList<String> newRemoteIpHeaderValue = new LinkedList<String>();
            
            remoteIpProxiesHeaderValue.add(originalRemoteAddr);
            
            String[] remoteIPHeaderValue = RemoteIpValve.commaDelimitedListToStringArray(request.getHeader(remoteIPHeader));
            int idx;
            // loop on remoteIPHeaderValue to find the first trusted remote ip and to build the proxies chain
            for (idx = remoteIPHeaderValue.length - 1; idx >= 0; idx--) {
                String currentRemoteIp = remoteIPHeaderValue[idx];
                remoteIp = currentRemoteIp;
                if (matchesOne(currentRemoteIp, trustedProxies)) {
                    remoteIpProxiesHeaderValue.addFirst(currentRemoteIp);
                } else {
                    idx--; // decrement idx because break doesn't do it
                    break;
                }
            }
            // continue to loop on remoteIPHeaderValue to build the new value of the RemoteIp header
            for (; idx >= 0; idx--) {
                String currentRemoteIp = remoteIPHeaderValue[idx];
                newRemoteIpHeaderValue.addFirst(currentRemoteIp);
            }
            if (remoteIp != null) {
                request.remoteHost = remoteIp;
                request.remoteAddr = remoteIp;
                
                // In Tomcat 6.0, Request.addHeader is no-op, use request.coyoteRequest.mimeHeaders.add
                if (remoteIpProxiesHeaderValue.size() == 0) {
                    request.getCoyoteRequest().getMimeHeaders().removeHeader(remoteIPProxiesHeader);
                } else {
                    String commaDelimitedListOfProxies = listToCommaDelimitedString(remoteIpProxiesHeaderValue);
                    request.getCoyoteRequest().getMimeHeaders().setValue(remoteIPProxiesHeader).setString(commaDelimitedListOfProxies);
                }
                if (newRemoteIpHeaderValue.size() == 0) {
                    request.getCoyoteRequest().getMimeHeaders().removeHeader(remoteIPHeader);
                } else {
                    String commaDelimitedRemoteIpHeaderValue = listToCommaDelimitedString(newRemoteIpHeaderValue);
                    request.getCoyoteRequest().getMimeHeaders().setValue(remoteIPHeader).setString(commaDelimitedRemoteIpHeaderValue);
                }
            }
        }
        try {
            getNext().invoke(request, response);
        } finally {
            request.remoteAddr = originalRemoteAddr;
            request.remoteHost = originalRemoteHost;
        }
    }
    
    protected boolean matchesOne(String str, Pattern[] patterns) {
        for (Pattern pattern : patterns) {
            if (pattern.matcher(str).matches()) {
                return true;
            }
        }
        return false;
    }
    
    public void setAllowedInternalProxies(String commaDelimitedAllowedInternalProxies) {
        this.allowedInternalProxies = commaDelimitedListToPatternArray(commaDelimitedAllowedInternalProxies);
    }
    
    /**
     * Name of the http header from which the remote ip is extracted.
     * <p>
     * Default value : <code>X-Forwarded-For</code>
     * </p>
     * 
     * @param remoteIPHeader
     */
    public void setRemoteIPHeader(String remoteIPHeader) {
        this.remoteIPHeader = remoteIPHeader;
    }
    
    public void setRemoteIPProxiesHeader(String remoteIPProxiesHeader) {
        this.remoteIPProxiesHeader = remoteIPProxiesHeader;
    }
    
    public void setTrustedProxies(String commaDelimitedTrustedProxies) {
        this.trustedProxies = commaDelimitedListToPatternArray(commaDelimitedTrustedProxies);
    }
}
