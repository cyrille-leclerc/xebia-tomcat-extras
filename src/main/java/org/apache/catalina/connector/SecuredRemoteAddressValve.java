/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletException;

import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * <p>
 * Sets {@link RequestFacade#isSecure()} to <code>true</code> if
 * {@link Request#getRemoteAddr()} matches one of the
 * <code>securedRemoteAddresses</code> of this valve.
 * </p>
 * <p>
 * This class must be located in <code>org.apache.catalina.connector</code> to
 * have access the <code>protected</code> variable {@link Request#facade}.
 * </p>
 */
public class SecuredRemoteAddressValve extends ValveBase {

    /**
     * {@link Pattern} for a comma delimited string that support whitespace
     * characters
     */
    private static final Pattern commaDelimitedValuesPattern = Pattern.compile("\\s*,\\s*");

    /**
     * Logger
     */
    private static Log log = LogFactory.getLog(SecuredRemoteAddressValve.class);

    /**
     * Convert a given comma delimited list of regular expressions into an array
     * of compiled {@link Pattern}
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
     * Convert a given comma delimited list of regular expressions into an array
     * of String
     */
    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {
        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaDelimitedValuesPattern
                .split(commaDelimitedStrings);
    }

    /**
     * Return <code>true</code> if the given <code>str</code> matches at least
     * one of the given <code>patterns</code>.
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
     * @see #setSecuredRemoteAddresses(String)
     */
    private Pattern[] securedRemoteAddresses = new Pattern[] { Pattern.compile("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"),
            Pattern.compile("192\\.168\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("172\\.(?:1[6-9]|2\\d|3[0-1]).\\d{1,3}.\\d{1,3}"),
            Pattern.compile("169\\.254\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}") };

    /**
     * @inheritDoc
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        final RequestFacade originalRequestFacade = request.facade;

        final boolean secure = request.isSecure() || matchesOne(request.getRemoteAddr(), securedRemoteAddresses);
        request.facade = new RequestFacade(request) {
            @Override
            public boolean isSecure() {
                return secure;
            }
        };

        if (log.isDebugEnabled()) {
            log.debug("Incoming request uri=" + request.getRequestURI() + " with secure='" + request.isSecure() + "', remoteAddr='"
                    + request.getRemoteAddr() + "' will be seen with requestFacade.secure='" + secure + "'");
        }

        try {
            getNext().invoke(request, response);
        } finally {
            request.facade = originalRequestFacade;
        }
    }

    /**
     * <p>
     * Comma delimited list of secured IP addresses. Expressed with regular
     * expressions.
     * </p>
     * <p>
     * Default value : 10\.\d{1,3}\.\d{1,3}\.\d{1,3},
     * 192\.168\.\d{1,3}\.\d{1,3}, 172\.(?:1[6-9]|2\d|3[0-1]).\d{1,3}.\d{1,3},
     * 169\.254\.\d{1,3}\.\d{1,3}, 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
     * </p>
     */
    public void setSecuredRemoteAddresses(String securedRemoteAddresses) {
        this.securedRemoteAddresses = commaDelimitedListToPatternArray(securedRemoteAddresses);
    }
}
