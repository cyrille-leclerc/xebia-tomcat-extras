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

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletException;

import org.apache.catalina.valves.ValveBase;
import org.junit.Test;

/**
 * {@link RemoteIpValve} Tests
 */
public class RemoteIpValveTest {
    
    static class RemoteAddrAndHostTrackerValve extends ValveBase {
        private String remoteAddr;
        private String remoteHost;
        
        public String getRemoteAddr() {
            return remoteAddr;
        }
        
        public String getRemoteHost() {
            return remoteHost;
        }
        
        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            this.remoteHost = request.getRemoteHost();
            this.remoteAddr = request.getRemoteAddr();
        }
    }
    
    @Test
    public void testCommaDelimitedListToStringArray() {
        List<String> elements = Arrays.asList("element1", "element2", "element3");
        String actual = RemoteIpValve.listToCommaDelimitedString(elements);
        assertEquals("element1, element2, element3", actual);
    }
    
    @Test
    public void testCommaDelimitedListToStringArrayEmptyList() {
        List<String> elements = new ArrayList<String>();
        String actual = RemoteIpValve.listToCommaDelimitedString(elements);
        assertEquals("", actual);
    }
    
    @Test
    public void testCommaDelimitedListToStringArrayNullList() {
        String actual = RemoteIpValve.listToCommaDelimitedString(null);
        assertEquals("", actual);
    }
    
    @Test
    public void testInvokeAllowedRemoteAddrWithNullRemoteIpHeader() throws Exception {
        // PREPARE
        RemoteIpValve remoteIpValve = new RemoteIpValve();
        remoteIpValve.setAllowedInternalProxies("internal-proxy1, internal-proxy2");
        remoteIpValve.setTrustedProxies("proxy1, proxy2, proxy3");
        remoteIpValve.setRemoteIPHeader("x-forwarded-for");
        remoteIpValve.setRemoteIPProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        remoteIpValve.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "internal-proxy1";
        request.remoteHost = "internal-proxy1-host";
        
        // TEST
        remoteIpValve.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertNull("x-forwarded-by must be null", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "internal-proxy1", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "internal-proxy1-host", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "internal-proxy1", actualPostInvokeRemoteAddr);

        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "internal-proxy1-host", actualPostInvokeRemoteHost);

    }
    
    @Test
    public void testInvokeAllProxiesAreTrusted() throws Exception {
        
        // PREPARE
        RemoteIpValve remoteIpValve = new RemoteIpValve();
        remoteIpValve.setAllowedInternalProxies("internal-proxy1, internal-proxy2");
        remoteIpValve.setTrustedProxies("proxy1, proxy2, proxy3");
        remoteIpValve.setRemoteIPHeader("x-forwarded-for");
        remoteIpValve.setRemoteIPProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        remoteIpValve.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "internal-proxy1";
        request.remoteHost = "internal-proxy1-host";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("client1, proxy1, proxy2");
        
        // TEST
        remoteIpValve.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("all proxies are trusted, x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("all proxies are trusted, they must appear in x-forwarded-by", "proxy1, proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "client1", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "client1", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "internal-proxy1", actualPostInvokeRemoteAddr);

        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "internal-proxy1-host", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeAllProxiesAreTrustedAndRemoteAddrMatchRegexp() throws Exception {
        
        // PREPARE
        RemoteIpValve remoteIpValve = new RemoteIpValve();
        remoteIpValve.setAllowedInternalProxies("127\\.0\\.0\\.1, 192\\.168\\..*, another-internal-proxy");
        remoteIpValve.setTrustedProxies("proxy1, proxy2, proxy3");
        remoteIpValve.setRemoteIPHeader("x-forwarded-for");
        remoteIpValve.setRemoteIPProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        remoteIpValve.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "internal-proxy1-host";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("client1, proxy1, proxy2");
        
        // TEST
        remoteIpValve.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("all proxies are trusted, x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("all proxies are trusted, they must appear in x-forwarded-by", "proxy1, proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "client1", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "client1", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);

        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "internal-proxy1-host", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeNotAllowedRemoteAddr() throws Exception {
        // PREPARE
        RemoteIpValve remoteIpValve = new RemoteIpValve();
        remoteIpValve.setAllowedInternalProxies("internal-proxy1, internal-proxy2");
        remoteIpValve.setTrustedProxies("proxy1, proxy2, proxy3");
        remoteIpValve.setRemoteIPHeader("x-forwarded-for");
        remoteIpValve.setRemoteIPProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        remoteIpValve.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "not-allowed-internal-proxy";
        request.remoteHost = "not-allowed-internal-proxy-host";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("client1, proxy1, proxy2");
        
        // TEST
        remoteIpValve.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertEquals("x-forwarded-for must be unchanged", "client1, proxy1, proxy2", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertNull("x-forwarded-by must be null", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "not-allowed-internal-proxy", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "not-allowed-internal-proxy-host", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "not-allowed-internal-proxy", actualPostInvokeRemoteAddr);

        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "not-allowed-internal-proxy-host", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeUntrustedProxyInTheChain() throws Exception {
        // PREPARE
        RemoteIpValve remoteIpValve = new RemoteIpValve();
        remoteIpValve.setAllowedInternalProxies("internal-proxy1, internal-proxy2");
        remoteIpValve.setTrustedProxies("proxy1, proxy2, proxy3");
        remoteIpValve.setRemoteIPHeader("x-forwarded-for");
        remoteIpValve.setRemoteIPProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        remoteIpValve.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "internal-proxy1";
        request.remoteHost = "internal-proxy1-host";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("client1, proxy1, untrusted-proxy, proxy2");
        
        // TEST
        remoteIpValve.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertEquals("ip/host before untrusted-proxy must appear in x-forwarded-for", "client1, proxy1", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("ip/host after untrusted-proxy must appear in  x-forwarded-by", "proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "untrusted-proxy", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "untrusted-proxy", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "internal-proxy1", actualPostInvokeRemoteAddr);

        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "internal-proxy1-host", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testListToCommaDelimitedString() {
        String[] actual = RemoteIpValve.commaDelimitedListToStringArray("element1, element2, element3");
        String[] expected = new String[] {
            "element1", "element2", "element3"
        };
        assertArrayEquals(expected, actual);
    }
    
    @Test
    public void testListToCommaDelimitedStringMixedSpaceChars() {
        String[] actual = RemoteIpValve.commaDelimitedListToStringArray("element1  , element2,\t element3");
        String[] expected = new String[] {
            "element1", "element2", "element3"
        };
        assertArrayEquals(expected, actual);
    }
}
