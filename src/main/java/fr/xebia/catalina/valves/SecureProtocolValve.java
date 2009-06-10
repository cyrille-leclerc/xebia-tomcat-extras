package fr.xebia.catalina.valves;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class SecureProtocolValve extends ValveBase {
    
    /**
     * {@link Pattern} for a comma delimited string that support whitespace characters
     */
    private static final Pattern commaSeparatedValuesPattern = Pattern.compile("\\s*,\\s*");
    
    /**
     * Logger
     */
    private static Log log = LogFactory.getLog(SecureProtocolValve.class);
    
    /**
     * Convert a given comma delimited list of regular expressions into an array of compiled {@link Pattern}
     */
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
    
    /**
     * Convert a given comma delimited list of regular expressions into an array of String
     */
    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {
        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaSeparatedValuesPattern
            .split(commaDelimitedStrings);
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
    private String protocolHeader = "X-Forwarded-Proto";
    
    private String protocolHeaderSslValue = "HTTPS";
    
    /**
     * @see #setSecuredRemoteAddresses(String)
     */
    private Pattern[] securedRemoteAddresses = new Pattern[] {
        Pattern.compile("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("192\\.168\\.\\d{1,3}\\.\\d{1,3}"),
        Pattern.compile("169\\.254\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
    };
    
    /**
     * @see #setSeeSecuredRemoteAddressesAsSsl(boolean)
     */
    private boolean seeSecuredRemoteAddressesAsSsl = false;
    
    /**
     * @inheritDoc
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        final String originalScheme = request.getScheme();
        final boolean originalSecure = request.isSecure();
        
        String scheme = originalScheme;
        boolean secure = originalSecure;
        if (matchesOne(request.getRemoteAddr(), internalProxies)) {
            String protocolHeaderValue = request.getHeader(protocolHeader);
            if (protocolHeaderValue != null) {
                scheme = protocolHeaderValue;
                if (protocolHeaderSslValue.equalsIgnoreCase(scheme)) {
                    secure = true;
                }
            }
        }
        
        if (matchesOne(request.getRemoteAddr(), securedRemoteAddresses)) {
            secure = true;
            if (seeSecuredRemoteAddressesAsSsl) {
                scheme = "https";
                
            }
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Incoming request.uri=" + request.getRequestURI() + ", request.scheme=" + originalScheme + ", request.secure="
                      + originalSecure + " will be seen as scheme=" + scheme + ", secure=" + secure);
        }
        
        request.setSecure(secure);
        // use request.coyoteRequest.scheme instead of request.setScheme() because request.setScheme() is no-op in Tomcat 6.0
        request.getCoyoteRequest().scheme().setString(scheme);
        try {
            getNext().invoke(request, response);
        } finally {
            request.setSecure(originalSecure);
            // use request.coyoteRequest.scheme instead of request.setScheme() because request.setScheme() is no-op in Tomcat 6.0
            request.getCoyoteRequest().scheme().setString(originalScheme);
        }
    }
    
    /**
     * <p>
     * Comma delimited list of internal proxies. Expressed with regular expressions.
     * </p>
     * <p>
     * Default value : 10\.\d{1,3}\.\d{1,3}\.\d{1,3}, 192\.168\.\d{1,3}\.\d{1,3}, 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
     * </p>
     */
    public void setInternalProxies(String commaAllowedInternalProxies) {
        this.internalProxies = commaDelimitedListToPatternArray(commaAllowedInternalProxies);
    }
    
    /**
     * Default value : <code>X-Forwarded-Proto</code>
     */
    public void setProtocolHeader(String protocolHeader) {
        this.protocolHeader = protocolHeader;
    }
    
    /**
     * <p>
     * Case insensitive value of the protocol header to indicate that the incoming http request uses SSL.
     * </p>
     * <p>
     * Default value : <code>HTTPS</code>
     * </p>
     */
    public void setProtocolHeaderSslValue(String protocolHeaderSslValue) {
        this.protocolHeaderSslValue = protocolHeaderSslValue;
    }
    
    /**
     * <p>
     * Comma delimited list of secured IP addresses proxies. Expressed with regular expressions.
     * </p>
     * <p>
     * Default value : 10\.\d{1,3}\.\d{1,3}\.\d{1,3}, 192\.168\.\d{1,3}\.\d{1,3}, 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
     * </p>
     */
    public void setSecuredRemoteAddresses(String securedRemoteAddresses) {
        this.securedRemoteAddresses = commaDelimitedListToPatternArray(securedRemoteAddresses);
    }
    
    /**
     * If set to <code>true</code>, http request coming from one of the secured remote addresses (see
     * {@link #setSecuredRemoteAddresses(String)}) will have the scheme https. Useful for frameworks like Spring Security which filter on
     * {@link HttpServletRequest#getScheme()} rather than {@link HttpServletRequest#isSecure()} .
     */
    public void setSeeSecuredRemoteAddressesAsSsl(boolean seeSecuredRemoteAddressesAsSsl) {
        this.seeSecuredRemoteAddressesAsSsl = seeSecuredRemoteAddressesAsSsl;
    }
    
}
