/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.druid.security.pac4j;

import org.apache.druid.server.security.AuthConfig;
import org.apache.druid.server.security.AuthenticationResult;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.engine.CallbackLogic;
import org.pac4j.core.engine.SecurityLogic;
import org.pac4j.core.profile.UserProfile;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class Pac4jFilterClaimsTest
{

  @Mock
  private Config pac4jConfig;
  @Mock
  private SessionStore sessionStore;
  @Mock
  private SecurityLogic<Object, JEEContext> securityLogic;
  @Mock
  private CallbackLogic<Object, JEEContext> callbackLogic;

  @Mock
  private HttpServletRequest req;
  @Mock
  private HttpServletResponse resp;
  @Mock
  private FilterChain chain;
  @Mock
  private UserProfile profile;

  private Pac4jFilter filter;

  @Before
  public void setUp() throws Exception
  {
    filter = new Pac4jFilter(
        "testPac4j",
        "basic",
        pac4jConfig,
        "whatever",
        "groups"
    );
    setField(filter, "sessionStore", sessionStore);
    setField(filter, "securityLogic", securityLogic);
    setField(filter, "callbackLogic", callbackLogic);

    when(req.getAttribute(AuthConfig.DRUID_AUTHENTICATION_RESULT)).thenReturn(null);
    when(req.getRequestURI()).thenReturn("/some/api");
  }

  @Test
  public void skipWhenAuthResultAlreadyPresent() throws IOException, ServletException
  {
    when(req.getAttribute(AuthConfig.DRUID_AUTHENTICATION_RESULT))
        .thenReturn(new AuthenticationResult("id", "a", "n", Map.of()));

    filter.doFilter(req, resp, chain);

    verify(chain, times(1)).doFilter(req, resp);
    verifyNoInteractions(securityLogic, callbackLogic);
  }

  @Test
  public void setsClaimContextWhenPresent() throws IOException, ServletException
  {
    when(profile.getId()).thenReturn("user1");
    when(profile.getAttribute("groups")).thenReturn(Arrays.asList("admin", "dev", "", "admin"));
    when(securityLogic.perform(
        any(JEEContext.class),
        eq(pac4jConfig),
        any(),
        any(),
        isNull(),
        eq("none"),
        isNull(),
        isNull()
    ))
        .thenReturn(profile);

    ArgumentCaptor<Object> authResCaptor = ArgumentCaptor.forClass(Object.class);

    filter.doFilter(req, resp, chain);

    verify(req).setAttribute(eq(AuthConfig.DRUID_AUTHENTICATION_RESULT), authResCaptor.capture());
    verify(chain, times(1)).doFilter(req, resp);

    AuthenticationResult ar = (AuthenticationResult) authResCaptor.getValue();
    assertEquals("user1", ar.getIdentity());
    assertNotNull(ar.getContext());
    assertTrue(ar.getContext().containsKey("profile"));
    Set<String> claimValues = (Set<String>) ar.getContext().get("oidcClaim");
    assertNotNull(claimValues);
    assertEquals(new HashSet<>(Arrays.asList("admin", "dev")), claimValues);
  }

  @Test
  public void fallsBackToIdentityWhenNoClaim() throws IOException, ServletException
  {
    when(profile.getId()).thenReturn("user2");
    when(profile.getAttribute("groups")).thenReturn(null);
    when(securityLogic.perform(
        any(JEEContext.class),
        eq(pac4jConfig),
        any(),
        any(),
        isNull(),
        eq("none"),
        isNull(),
        isNull()
    ))
        .thenReturn(profile);

    ArgumentCaptor<Object> authResCaptor = ArgumentCaptor.forClass(Object.class);

    filter.doFilter(req, resp, chain);

    verify(req).setAttribute(eq(AuthConfig.DRUID_AUTHENTICATION_RESULT), authResCaptor.capture());
    AuthenticationResult ar = (AuthenticationResult) authResCaptor.getValue();
    assertEquals("user2", ar.getIdentity());
    assertNotNull(ar.getContext());
    assertFalse(ar.getContext().containsKey("oidcClaim"));
    verify(chain, times(1)).doFilter(req, resp);
  }

  @Test
  public void normalizesArrayClaim() throws IOException, ServletException
  {
    when(profile.getId()).thenReturn("user3");
    when(profile.getAttribute("groups")).thenReturn(new String[]{"ops", " ", "ops", "auditor"});
    when(securityLogic.perform(
        any(JEEContext.class),
        eq(pac4jConfig),
        any(),
        any(),
        isNull(),
        eq("none"),
        isNull(),
        isNull()
    ))
        .thenReturn(profile);

    ArgumentCaptor<Object> authResCaptor = ArgumentCaptor.forClass(Object.class);

    filter.doFilter(req, resp, chain);

    verify(req).setAttribute(eq(AuthConfig.DRUID_AUTHENTICATION_RESULT), authResCaptor.capture());

    AuthenticationResult ar = (AuthenticationResult) authResCaptor.getValue();
    Set<String> claimValues = (Set<String>) ar.getContext().get("oidcClaim");
    assertEquals(new HashSet<>(Arrays.asList("ops", "auditor")), claimValues);
  }

  @Test
  public void noProfileDoesNotSetAuthResult() throws IOException, ServletException
  {
    when(securityLogic.perform(
        any(JEEContext.class),
        eq(pac4jConfig),
        any(),
        any(),
        isNull(),
        eq("none"),
        isNull(),
        isNull()
    ))
        .thenReturn(null);

    filter.doFilter(req, resp, chain);

    verify(req, never()).setAttribute(eq(AuthConfig.DRUID_AUTHENTICATION_RESULT), any());
    verify(chain, never()).doFilter(any(), any());
  }

  private static void setField(Object target, String name, Object value) throws Exception
  {
    Field f = target.getClass().getDeclaredField(name);
    f.setAccessible(true);
    f.set(target, value);
  }
}
