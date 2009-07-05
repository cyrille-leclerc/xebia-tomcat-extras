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
package fr.xebia.servlet.filter;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.RemoteIpValve;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Servlet filter to integrate "X-Forwarded-For" and "X-Forwarded-Proto" HYYP headers.
 * 
 * @author <a href="mailto:cyrille.leclerc@pobox.com">Cyrille Le Clerc</a>
 */
public class XForwardedForFilter implements Filter {
    
    public static class XForwardedRequest extends HttpServletRequestWrapper {
        
        final static ThreadLocal<SimpleDateFormat[]> threadLocalDateFormats = new ThreadLocal<SimpleDateFormat[]>() {
            protected SimpleDateFormat[] initialValue() {
                return new SimpleDateFormat[] {
                    new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US),
                    new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US),
                    new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US)
                };
                
            };
        };
        
        protected Map<String, List<String>> headers;
        
        protected String remoteAddr;
        
        protected String remoteHost;
        
        protected String scheme;
        
        protected boolean secure;
        
        @SuppressWarnings("unchecked")
        public XForwardedRequest(HttpServletRequest request) {
            super(request);
            this.remoteAddr = request.getRemoteAddr();
            this.remoteHost = request.getRemoteHost();
            this.scheme = request.getScheme();
            this.secure = request.isSecure();
            
            headers = new HashMap<String, List<String>>();
            for (Enumeration<String> headerNames = request.getHeaderNames(); headerNames.hasMoreElements();) {
                String header = headerNames.nextElement();
                headers.put(header, Collections.list(request.getHeaders(header)));
            }
        }
        
        @Override
        public long getDateHeader(String name) {
            String value = getHeader(name);
            if (value == null) {
                return -1;
            }
            DateFormat[] dateFormats = threadLocalDateFormats.get();
            Date date = null;
            for (int i = 0; ((i < dateFormats.length) && (date == null)); i++) {
                DateFormat dateFormat = dateFormats[i];
                try {
                    date = dateFormat.parse(value);
                } catch (Exception ParseException) {
                    ;
                }
            }
            if (date == null) {
                throw new IllegalArgumentException(value);
            } else {
                return date.getTime();
            }
        }
        
        @Override
        public String getHeader(String name) {
            List<String> values = headers.get(name);
            if (values == null || values.isEmpty()) {
                return null;
            } else {
                return values.get(0);
            }
        }
        
        @Override
        public Enumeration<?> getHeaderNames() {
            return Collections.enumeration(headers.keySet());
        }
        
        @Override
        public Enumeration<?> getHeaders(String name) {
            List<String> values = headers.get(name);
            if (values == null) {
                values = Collections.emptyList();
            }
            return Collections.enumeration(values);
        }
        
        @Override
        public int getIntHeader(String name) {
            String value = getHeader(name);
            if (value == null) {
                return -1;
            } else {
                return Integer.parseInt(value);
            }
        }
        
        @Override
        public String getRemoteAddr() {
            return this.remoteAddr;
        }
        
        @Override
        public String getRemoteHost() {
            return this.remoteHost;
        }
        
        public String getScheme() {
            return scheme;
        }
        
        public boolean isSecure() {
            return secure;
        }
        
        public void removeHeader(String name) {
            headers.remove(name);
        }
        
        public void setHeader(String name, String value) {
            headers.put(name, Arrays.asList(value));
        }
        
        public void setRemoteAddr(String remoteAddr) {
            this.remoteAddr = remoteAddr;
        }
        
        public void setRemoteHost(String remoteHost) {
            this.remoteHost = remoteHost;
        }
        
        public void setScheme(String scheme) {
            this.scheme = scheme;
        }
        
        public void setSecure(boolean secure) {
            this.secure = secure;
        }
    }
    
    /**
     * {@link Pattern} for a comma delimited string that support whitespace characters
     */
    private static final Pattern commaSeparatedValuesPattern = Pattern.compile("\\s*,\\s*");
    
    /**
     * Logger
     */
    private static Log log = LogFactory.getLog(XForwardedForFilter.class);
    
    /**
     * Convert a given comma delimited list of regular expressions into an array of compiled {@link Pattern}
     * 
     * @return array of patterns (not <code>null</code>)
     */
    protected static Pattern[] commaDelimitedListToPatternArray(String commaDelimitedPatterns) {
        String[] patterns = commaDelimitedListToStringArray(commaDelimitedPatterns);
        List<Pattern> patternsList = new ArrayList<Pattern>();
        for (String pattern : patterns) {
            try {
                patternsList.add(Pattern.compile(pattern));
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException("Illegal pattern syntax '" + pattern + "'", e);
            }
        }
        return patternsList.toArray(new Pattern[0]);
    }
    
    /**
     * Convert a given comma delimited list of regular expressions into an array of String
     * 
     * @return array of patterns (non <code>null</code>)
     */
    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {
        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaSeparatedValuesPattern
            .split(commaDelimitedStrings);
    }
    
    /**
     * Convert an array of strings in a comma delimited string
     */
    protected static String listToCommaDelimitedString(List<String> stringList) {
        if (stringList == null) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (Iterator<String> it = stringList.iterator(); it.hasNext();) {
            Object element = it.next();
            if (element != null) {
                result.append(element);
                if (it.hasNext()) {
                    result.append(", ");
                }
            }
        }
        return result.toString();
    }
    
    /**
     * Return <code>true</code> if the given <code>str</code> matches at least one of the given <code>patterns</code>.
     */
    protected static boolean matchesOne(String str, Pattern... patterns) {
        for (Pattern pattern : patterns) {
            if (pattern.matcher(str).matches()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * @see #setInternalProxies(String)
     */
    private Pattern[] internalProxies = new Pattern[] {
        Pattern.compile("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("192\\.168\\.\\d{1,3}\\.\\d{1,3}"),
        Pattern.compile("169\\.254\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
    };
    
    /**
     * @see #setProtocolHeader(String)
     */
    private String protocolHeader = null;
    
    private String protocolHeaderSslValue = "https";
    
    /**
     * @see #setProxiesHeader(String)
     */
    private String proxiesHeader = "X-Forwarded-By";
    
    /**
     * @see #setRemoteIPHeader(String)
     */
    private String remoteIPHeader = "X-Forwarded-For";
    
    /**
     * @see RemoteIpValve#setTrustedProxies(String)
     */
    private Pattern[] trustedProxies = new Pattern[0];
    
    public void destroy() {
    }
    
    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        if (matchesOne(request.getRemoteAddr(), internalProxies)) {
            String remoteIp = null;
            // In java 6, proxiesHeaderValue should be declared as a java.util.Deque
            LinkedList<String> proxiesHeaderValue = new LinkedList<String>();
            
            String[] remoteIPHeaderValue = commaDelimitedListToStringArray(request.getHeader(remoteIPHeader));
            int idx;
            // loop on remoteIPHeaderValue to find the first trusted remote ip and to build the proxies chain
            for (idx = remoteIPHeaderValue.length - 1; idx >= 0; idx--) {
                String currentRemoteIp = remoteIPHeaderValue[idx];
                remoteIp = currentRemoteIp;
                if (matchesOne(currentRemoteIp, internalProxies)) {
                    // do nothing, internalProxies IPs are not appended to the
                } else if (matchesOne(currentRemoteIp, trustedProxies)) {
                    proxiesHeaderValue.addFirst(currentRemoteIp);
                } else {
                    idx--; // decrement idx because break statement doesn't do it
                    break;
                }
            }
            // continue to loop on remoteIPHeaderValue to build the new value of the remoteIPHeader
            LinkedList<String> newRemoteIpHeaderValue = new LinkedList<String>();
            for (; idx >= 0; idx--) {
                String currentRemoteIp = remoteIPHeaderValue[idx];
                newRemoteIpHeaderValue.addFirst(currentRemoteIp);
            }
            
            XForwardedRequest xRequest = new XForwardedRequest(request);
            if (remoteIp != null) {
                
                xRequest.setRemoteAddr(remoteIp);
                xRequest.setRemoteHost(remoteIp);
                
                if (proxiesHeaderValue.size() == 0) {
                    xRequest.removeHeader(proxiesHeader);
                } else {
                    String commaDelimitedListOfProxies = listToCommaDelimitedString(proxiesHeaderValue);
                    xRequest.setHeader(proxiesHeader, commaDelimitedListOfProxies);
                }
                if (newRemoteIpHeaderValue.size() == 0) {
                    xRequest.removeHeader(remoteIPHeader);
                } else {
                    String commaDelimitedRemoteIpHeaderValue = listToCommaDelimitedString(newRemoteIpHeaderValue);
                    xRequest.setHeader(remoteIPHeader, commaDelimitedRemoteIpHeaderValue);
                }
            }
            
            if (protocolHeader != null) {
                String protocolHeaderValue = request.getHeader(protocolHeader);
                if (protocolHeaderValue != null && protocolHeaderSslValue.equalsIgnoreCase(protocolHeaderValue)) {
                    xRequest.setSecure(true);
                    xRequest.setScheme("https");
                }
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Incoming request " + request.getRequestURI() + " with originalRemoteAddr '" + request.getRemoteAddr()
                          + "', originalRemoteHost='" + request.getRemoteHost() + "', originalSecure='" + request.isSecure()
                          + "', originalScheme='" + request.getScheme() + "' will be seen as newRemoteAddr='" + xRequest.getRemoteAddr()
                          + "', newRemoteHost='" + xRequest.getRemoteHost() + "', newScheme='" + xRequest.getScheme() + "', newSecure='"
                          + xRequest.isSecure() + "'");
            }
            chain.doFilter(xRequest, response);
        } else {
            chain.doFilter(request, response);
        }
        
    }
    
    /**
     * Wrap the incoming <code>request</code> in a {@link XForwardedRequest} if the http header <code>x-forwareded-for</code> is not empty.
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            doFilter((HttpServletRequest)request, (HttpServletResponse)response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }
    
    public Pattern[] getInternalProxies() {
        return internalProxies;
    }
    
    public String getProtocolHeader() {
        return protocolHeader;
    }
    
    public String getProtocolHeaderSslValue() {
        return protocolHeaderSslValue;
    }
    
    public String getProxiesHeader() {
        return proxiesHeader;
    }
    
    public String getRemoteIPHeader() {
        return remoteIPHeader;
    }
    
    public Pattern[] getTrustedProxies() {
        return trustedProxies;
    }
    
    public void init(FilterConfig filterConfig) throws ServletException {
        if (filterConfig.getInitParameter("InternalProxies") != null) {
            this.internalProxies = commaDelimitedListToPatternArray(filterConfig.getInitParameter("InternalProxies"));
        }
        
        if (filterConfig.getInitParameter("ProtocolHeader") != null) {
            this.protocolHeader = filterConfig.getInitParameter("ProtocolHeader");
        }
        
        if (filterConfig.getInitParameter("ProtocolHeaderSslValue") != null) {
            this.protocolHeaderSslValue = filterConfig.getInitParameter("ProtocolHeaderSslValue");
        }
        
        if (filterConfig.getInitParameter("ProxiesHeader") != null) {
            this.proxiesHeader = filterConfig.getInitParameter("ProxiesHeader");
        }
        
        if (filterConfig.getInitParameter("RemoteIPHeader") != null) {
            this.remoteIPHeader = filterConfig.getInitParameter("RemoteIPHeader");
        }
        
        if (filterConfig.getInitParameter("TrustedProxies") != null) {
            this.trustedProxies = commaDelimitedListToPatternArray(filterConfig.getInitParameter("TrustedProxies"));
        }
        
    }
    
}
