package fr.xebia.servlet.filter;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.Test;

public class XForwardedForFilterTest {
    
    public static class ConfigurableFilterConfig implements FilterConfig {
        
        private Map<String, String> initParameters = new HashMap<String, String>();
        
        public String getFilterName() {
            return null;
        }
        
        public String getInitParameter(String name) {
            return initParameters.get(name);
        }
        
        public Enumeration<?> getInitParameterNames() {
            return Collections.enumeration(initParameters.keySet());
        }
        
        public ServletContext getServletContext() {
            return null;
        }
        
        public void setInitParameter(String name, String value) {
            initParameters.put(name, value);
        }
        
    }
    
    @Test
    public void testCommaDelimitedListToStringArray() {
        List<String> elements = Arrays.asList("element1", "element2", "element3");
        String actual = XForwardedForFilter.listToCommaDelimitedString(elements);
        assertEquals("element1, element2, element3", actual);
    }
    
    @Test
    public void testCommaDelimitedListToStringArrayEmptyList() {
        List<String> elements = new ArrayList<String>();
        String actual = XForwardedForFilter.listToCommaDelimitedString(elements);
        assertEquals("", actual);
    }
    
    @Test
    public void testCommaDelimitedListToStringArrayNullList() {
        String actual = XForwardedForFilter.listToCommaDelimitedString(null);
        assertEquals("", actual);
    }
    
    @Test
    public void testInvokeAllowedRemoteAddrWithNullRemoteIpHeader() throws Exception {
        // PREPARE
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("192\\.168\\.0\\.10, 192\\.168\\.0\\.11");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "remote-host-original-value";
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertNull("x-forwarded-by must be null", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "192.168.0.10", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "remote-host-original-value", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);
        
        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "remote-host-original-value", actualPostInvokeRemoteHost);
        
    }
    
    @Test
    public void testInvokeAllProxiesAreTrusted() throws Exception {
        
        // PREPARE
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("192\\.168\\.0\\.10, 192\\.168\\.0\\.11");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "remote-host-original-value";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("140.211.11.130, proxy1, proxy2");
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("all proxies are trusted, x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("all proxies are trusted, they must appear in x-forwarded-by", "proxy1, proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "140.211.11.130", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "140.211.11.130", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);
        
        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "remote-host-original-value", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeAllProxiesAreTrustedOrInternal() throws Exception {
        
        // PREPARE
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("192\\.168\\.0\\.10, 192\\.168\\.0\\.11");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "remote-host-original-value";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for")
            .setString("140.211.11.130, proxy1, proxy2, 192.168.0.10, 192.168.0.11");
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("all proxies are trusted, x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("all proxies are trusted, they must appear in x-forwarded-by", "proxy1, proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "140.211.11.130", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "140.211.11.130", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);
        
        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "remote-host-original-value", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeAllProxiesAreInternal() throws Exception {
        
        // PREPARE
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("192\\.168\\.0\\.10, 192\\.168\\.0\\.11");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "remote-host-original-value";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("140.211.11.130, 192.168.0.10, 192.168.0.11");
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("all proxies are internal, x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertNull("all proxies are internal, x-forwarded-by must be null", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "140.211.11.130", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "140.211.11.130", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);
        
        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "remote-host-original-value", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeAllProxiesAreTrustedAndRemoteAddrMatchRegexp() throws Exception {
        
        // PREPARE
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("127\\.0\\.0\\.1, 192\\.168\\..*, another-internal-proxy");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "remote-host-original-value";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("140.211.11.130, proxy1, proxy2");
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertNull("all proxies are trusted, x-forwarded-for must be null", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("all proxies are trusted, they must appear in x-forwarded-by", "proxy1, proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "140.211.11.130", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "140.211.11.130", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);
        
        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "remote-host-original-value", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testInvokeNotAllowedRemoteAddr() throws Exception {
        // PREPARE
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("192\\.168\\.0\\.10, 192\\.168\\.0\\.11");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "not-allowed-internal-proxy";
        request.remoteHost = "not-allowed-internal-proxy-host";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for").setString("140.211.11.130, proxy1, proxy2");
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertEquals("x-forwarded-for must be unchanged", "140.211.11.130, proxy1, proxy2", actualXForwardedFor);
        
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
        XForwardedForFilter XForwardedForFilter = new XForwardedForFilter();
        ConfigurableFilterConfig filterConfig = new ConfigurableFilterConfig();
        XForwardedForFilter.setInternalProxies("192\\.168\\.0\\.10, 192\\.168\\.0\\.11");
        XForwardedForFilter.setTrustedProxies("proxy1, proxy2, proxy3");
        XForwardedForFilter.setRemoteIPHeader("x-forwarded-for");
        XForwardedForFilter.setProxiesHeader("x-forwarded-by");
        RemoteAddrAndHostTrackerValve remoteAddrAndHostTrackerValve = new RemoteAddrAndHostTrackerValve();
        XForwardedForFilter.setNext(remoteAddrAndHostTrackerValve);
        
        Request request = new Request();
        request.setCoyoteRequest(new org.apache.coyote.Request());
        request.remoteAddr = "192.168.0.10";
        request.remoteHost = "remote-host-original-value";
        request.getCoyoteRequest().getMimeHeaders().addValue("x-forwarded-for")
            .setString("140.211.11.130, proxy1, untrusted-proxy, proxy2");
        
        // TEST
        XForwardedForFilter.invoke(request, null);
        
        // VERIFY
        String actualXForwardedFor = request.getHeader("x-forwarded-for");
        assertEquals("ip/host before untrusted-proxy must appear in x-forwarded-for", "140.211.11.130, proxy1", actualXForwardedFor);
        
        String actualXForwardedBy = request.getHeader("x-forwarded-by");
        assertEquals("ip/host after untrusted-proxy must appear in  x-forwarded-by", "proxy2", actualXForwardedBy);
        
        String actualRemoteAddr = remoteAddrAndHostTrackerValve.getRemoteAddr();
        assertEquals("remoteAddr", "untrusted-proxy", actualRemoteAddr);
        
        String actualRemoteHost = remoteAddrAndHostTrackerValve.getRemoteHost();
        assertEquals("remoteHost", "untrusted-proxy", actualRemoteHost);
        
        String actualPostInvokeRemoteAddr = request.getRemoteAddr();
        assertEquals("postInvoke remoteAddr", "192.168.0.10", actualPostInvokeRemoteAddr);
        
        String actualPostInvokeRemoteHost = request.getRemoteHost();
        assertEquals("postInvoke remoteAddr", "remote-host-original-value", actualPostInvokeRemoteHost);
    }
    
    @Test
    public void testListToCommaDelimitedString() {
        String[] actual = XForwardedForFilter.commaDelimitedListToStringArray("element1, element2, element3");
        String[] expected = new String[] {
            "element1", "element2", "element3"
        };
        assertArrayEquals(expected, actual);
    }
    
    @Test
    public void testListToCommaDelimitedStringMixedSpaceChars() {
        String[] actual = XForwardedForFilter.commaDelimitedListToStringArray("element1  , element2,\t element3");
        String[] expected = new String[] {
            "element1", "element2", "element3"
        };
        assertArrayEquals(expected, actual);
    }
    
}
