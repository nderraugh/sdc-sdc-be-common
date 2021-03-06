/*-
 * ============LICENSE_START=======================================================
 * SDC
 * ================================================================================
 * Copyright (C) 2017 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
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
 * ============LICENSE_END=========================================================
 */

package org.onap.sdc.security.filters;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.FixMethodOrder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.onap.sdc.security.AuthenticationCookie;
import org.onap.sdc.security.AuthenticationCookieUtils;
import org.onap.sdc.security.CipherUtilException;
import org.onap.sdc.security.RepresentationUtils;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SessionValidationFilterTest {


    private final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

    private final HttpServletResponse response = Mockito.spy(HttpServletResponse.class);

    private final FilterChain filterChain = Mockito.mock(FilterChain.class);

    private final FilterConfig filterConfig = Mockito.mock(FilterConfig.class);

    // implementation of SessionValidationFilter
    private final SampleFilter sessionValidationFilter = Mockito.spy(SampleFilter.class);

    @BeforeEach
    public void setUpClass() {
        sessionValidationFilter.init(filterConfig);
    }

    @Test
    public void excludedUrlHealthcheck() throws IOException, ServletException {
        when(request.getPathInfo()).thenReturn("/healthCheck");
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    public void excludedUrlUpload() throws IOException, ServletException {
        when(request.getPathInfo()).thenReturn("/upload/123");
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    // case when url pattern in web.xml is forward slash (/)
    @Test
    public void pathInfoIsNull() throws IOException, ServletException {
        when(request.getServletPath()).thenReturn("/upload/2");
        when(request.getPathInfo()).thenReturn(null);
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    public void noCookiesInRequest() throws IOException, ServletException {
        when(request.getPathInfo()).thenReturn("/resource");
        when(request.getCookies()).thenReturn(new Cookie[0]);
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(1)).handleRedirectException(response);
    }

    @Test
    public void nullCookiesInRequest() throws IOException, ServletException {
        when(request.getPathInfo()).thenReturn("/resource");
        when(request.getCookies()).thenReturn(null);
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(1)).handleRedirectException(response);
    }

    @Test
    public void noCookiesWithCorrectNameInRequest() throws IOException, ServletException {
        when(request.getPathInfo()).thenReturn("/resource");
        String newNameNotContainsRealName = sessionValidationFilter.getFilterConfiguration().getCookieName()
            .substring(1);
        Cookie cookie = new Cookie("fake" + newNameNotContainsRealName + "fake2",
            RepresentationUtils.toRepresentation(new AuthenticationCookie("kuku")));
        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(1)).handleRedirectException(response);
    }

    @Test
    public void cookieMaxSessionTimedOutAndUserIsNotAuthorized()
        throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");
        AuthenticationCookie authenticationCookie = new AuthenticationCookie(SampleFilter.FAILED_ON_USER_AUTH);
        // set max session time to timout value
        long maxSessionTimeOut = sessionValidationFilter.getFilterConfiguration().getMaxSessionTimeOut();
        long startTime = authenticationCookie.getMaxSessionTime();
        long timeout = startTime - maxSessionTimeOut - 1000L;
        authenticationCookie.setMaxSessionTime(timeout);
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(1)).handleRedirectException(response);
    }

    @Test
    public void cookieMaxSessionTimedOutAndUserIsAuthorized()
        throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");
        AuthenticationCookie authenticationCookie = new AuthenticationCookie("userId");
        // set max session time to timout value
        long maxSessionTimeOut = sessionValidationFilter.getFilterConfiguration().getMaxSessionTimeOut();
        long startTime = authenticationCookie.getMaxSessionTime();
        long timeout = startTime - maxSessionTimeOut - 1000L;
        authenticationCookie.setMaxSessionTime(timeout);
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    public void cookieSessionIdleAndUserIsNotAuthorized() throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");
        AuthenticationCookie authenticationCookie = new AuthenticationCookie(SampleFilter.FAILED_ON_USER_AUTH);
        // set session time to timout to idle
        long idleSessionTimeOut = sessionValidationFilter.getFilterConfiguration().getSessionIdleTimeOut();
        long sessionStartTime = authenticationCookie.getCurrentSessionTime();
        long timeout = sessionStartTime - idleSessionTimeOut - 2000;
        authenticationCookie.setCurrentSessionTime(timeout);
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(1)).handleRedirectException(response);
    }

    @Test
    public void cookieSessionIdleAndUserIsAuthorized() throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");
        AuthenticationCookie authenticationCookie = new AuthenticationCookie("kuku");
        // set session time to timout to idle
        long idleSessionTimeOut = sessionValidationFilter.getFilterConfiguration().getSessionIdleTimeOut();
        long sessionStartTime = authenticationCookie.getCurrentSessionTime();
        long timeout = sessionStartTime - idleSessionTimeOut - 2000;
        authenticationCookie.setCurrentSessionTime(timeout);
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    public void cookieSessionIsNotExpiredRoleAssignmentDone()
        throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");
        AuthenticationCookie authenticationCookie = new AuthenticationCookie(SampleFilter.FAILED_ON_ROLE);
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(0)).handleRedirectException(response);
    }


    @Test
    public void requestThatPassFilter() throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");

        AuthenticationCookie authenticationCookie = new AuthenticationCookie("kuku");
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    //    test validate contains
    @Test
    public void requestThatPassFilterWithCookieNameAsPartOfOtherString()
        throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");

        AuthenticationCookie authenticationCookie = new AuthenticationCookie("kuku");
        Cookie cookie = new Cookie("some" + sessionValidationFilter.getFilterConfiguration().getCookieName() + "Thing",
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    public void w_requestThatThrowCipherUtilException() throws IOException, ServletException, CipherUtilException {
        when(request.getPathInfo()).thenReturn("/resource");

        AuthenticationCookie authenticationCookie = new AuthenticationCookie("kuku");
        Cookie cookie = new Cookie(sessionValidationFilter.getFilterConfiguration().getCookieName(),
            AuthenticationCookieUtils
                .getEncryptedCookie(authenticationCookie, sessionValidationFilter.getFilterConfiguration()));

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        String oldKey = sessionValidationFilter.getFilterConfiguration().getSecurityKey();
        sessionValidationFilter.setSecurityKey("");
        sessionValidationFilter.doFilter(request, response, filterChain);
        Mockito.verify(sessionValidationFilter, times(1)).handleRedirectException(response);
        sessionValidationFilter.setSecurityKey(oldKey);
    }

}