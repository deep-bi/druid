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

import net.minidev.json.JSONArray;
import org.apache.druid.server.security.Access;
import org.apache.druid.server.security.Action;
import org.apache.druid.server.security.AuthenticationResult;
import org.apache.druid.server.security.Resource;
import org.apache.druid.server.security.ResourceAction;
import org.apache.druid.server.security.ResourceType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class Pac4jAuthorizerTest
{

  @Mock
  private OIDCConfig oidcConfig;
  @Mock
  private PermissionsCollector permissionsCollector;

  private Pac4jAuthorizer authorizer;

  @Before
  public void setUp()
  {
    authorizer = new Pac4jAuthorizer(oidcConfig, permissionsCollector);
  }

  @Test
  public void allowsWhenClaimNameNull()
  {
    when(oidcConfig.getOidcClaim()).thenReturn(null);
    AuthenticationResult ar = auth(emptyContext());
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertTrue(a.isAllowed());
    verifyNoInteractions(permissionsCollector);
  }

  @Test
  public void allowsWhenClaimNameBlank()
  {
    when(oidcConfig.getOidcClaim()).thenReturn("  ");
    AuthenticationResult ar = auth(emptyContext());
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertTrue(a.isAllowed());
    verifyNoInteractions(permissionsCollector);
  }

  @Test
  public void deniesWhenAuthenticationNull()
  {
    Access a = authorizer.authorize(null, res("x"), Action.READ);
    assertFalse(a.isAllowed());
    verifyNoInteractions(permissionsCollector);
  }

  @Test
  public void deniesWhenContextNull()
  {
    AuthenticationResult ar = new AuthenticationResult("u", "pac4j", "pac4j", null);
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertFalse(a.isAllowed());
    verifyNoInteractions(permissionsCollector);
  }

  @Test
  public void deniesWhenGroupClaimMissing()
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    AuthenticationResult ar = auth(mapOf());
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertFalse(a.isAllowed());
    verifyNoInteractions(permissionsCollector);
  }

  @Test
  public void deniesWhenGroupsEmptyArray()
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    AuthenticationResult ar = auth(mapOf(arr));
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertFalse(a.isAllowed());
    verifyNoInteractions(permissionsCollector);
  }

  @Test
  public void deniesWhenCollectorReturnsEmpty() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    arr.add("analyst");
    AuthenticationResult ar = auth(mapOf(arr));
    when(permissionsCollector.collect(anySet())).thenReturn(Collections.emptyList());
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertFalse(a.isAllowed());
  }

  @Test
  public void allowsOnExactMatch() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    arr.add("analyst");
    AuthenticationResult ar = auth(mapOf(arr));
    when(permissionsCollector.collect(anySet()))
        .thenReturn(List.of(permission(ResourceType.DATASOURCE, Pattern.compile("sales_2025"))));
    Access a = authorizer.authorize(ar, res("sales_2025"), Action.READ);
    assertTrue(a.isAllowed());
  }

  @Test
  public void allowsOnRegexMatch() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    arr.add("analyst");
    AuthenticationResult ar = auth(mapOf(arr));
    when(permissionsCollector.collect(anySet()))
        .thenReturn(List.of(permission(ResourceType.DATASOURCE, Pattern.compile("sales_.*"))));
    Access a = authorizer.authorize(ar, res("sales_2026"), Action.READ);
    assertTrue(a.isAllowed());
  }

  @Test
  public void allowsOnWildcardEquivalent() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    arr.add("admin");
    AuthenticationResult ar = auth(mapOf(arr));
    when(permissionsCollector.collect(anySet()))
        .thenReturn(List.of(permission(ResourceType.DATASOURCE, Pattern.compile(".*"))));
    Access a = authorizer.authorize(ar, res("any"), Action.READ);
    assertTrue(a.isAllowed());
  }

  @Test
  public void deniesOnActionMismatch() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    arr.add("writer");
    AuthenticationResult ar = auth(mapOf(arr));
    when(permissionsCollector.collect(anySet()))
        .thenReturn(List.of(permission(ResourceType.DATASOURCE, Pattern.compile("sales_2025"))));
    Access a = authorizer.authorize(ar, res("sales_2025"), Action.WRITE);
    assertFalse(a.isAllowed());
  }

  @Test
  public void deniesOnTypeMismatch() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    JSONArray arr = new JSONArray();
    arr.add("analyst");
    AuthenticationResult ar = auth(mapOf(arr));
    when(permissionsCollector.collect(anySet()))
        .thenReturn(List.of(permission(ResourceType.CONFIG, Pattern.compile(".*"))));
    Access a = authorizer.authorize(ar, res("sales_2025"), Action.READ);
    assertFalse(a.isAllowed());
  }

  @Test
  public void supportsStringGroupClaimWithDelimiters() throws Exception
  {
    when(oidcConfig.getOidcClaim()).thenReturn("groups");
    AuthenticationResult ar = auth(mapOf("analyst, admin"));
    when(permissionsCollector.collect(anySet()))
        .thenReturn(List.of(permission(ResourceType.DATASOURCE, Pattern.compile(".*"))));
    Access a = authorizer.authorize(ar, res("x"), Action.READ);
    assertTrue(a.isAllowed());
  }

  private static Resource res(String name)
  {
    return new Resource(name, ResourceType.DATASOURCE);
  }

  private AuthenticationResult auth(Map<String, Object> ctx)
  {
    return new AuthenticationResult("u", "pac4j", "pac4j", ctx);
  }

  private static Map<String, Object> emptyContext()
  {
    return new HashMap<>();
  }

  private static Map<String, Object> mapOf()
  {
    return new HashMap<>();
  }

  private static Map<String, Object> mapOf(Object v)
  {
    Map<String, Object> m = new HashMap<>();
    m.put("groups", v);
    return m;
  }

  private static PermissionDto permission(String type, Pattern namePattern)
  {
    return new PermissionDto(
        new ResourceAction(new Resource("ignored", type), Action.READ),
        namePattern
    );
  }
}
