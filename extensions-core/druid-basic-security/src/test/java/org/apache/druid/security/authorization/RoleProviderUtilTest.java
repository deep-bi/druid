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

package org.apache.druid.security.authorization;

import org.apache.druid.security.basic.authorization.RoleProviderUtil;
import org.apache.druid.security.basic.authorization.db.cache.BasicAuthorizerCacheManager;
import org.apache.druid.security.basic.authorization.entity.BasicAuthorizerRole;
import org.apache.druid.security.basic.authorization.entity.BasicAuthorizerUser;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class RoleProviderUtilTest
{

  @Test
  public void getRolesByIdentityAddsRolesWhenUserFound()
  {
    Set<String> roles = new HashSet<>(Arrays.asList("r1", "r2"));
    BasicAuthorizerUser user = new BasicAuthorizerUser("id", roles);

    Map<String, BasicAuthorizerUser> userMap = new HashMap<>();
    userMap.put("id", user);

    Set<String> out = RoleProviderUtil.getRolesByIdentity(userMap, "id", new HashSet<>());
    assertEquals(roles, out);
  }

  @Test
  public void getRolesByIdentityNoopWhenUserMissing()
  {
    Map<String, BasicAuthorizerUser> userMap = new HashMap<>();
    Set<String> out = RoleProviderUtil.getRolesByIdentity(userMap, "missing", new HashSet<>());
    assertTrue(out.isEmpty());
  }

  @Test
  public void getRolesByClaimValuesFiltersByRoleNames()
  {
    Map<String, BasicAuthorizerRole> roles = new HashMap<>();
    roles.put("r1", null);
    roles.put("r2", null);

    BasicAuthorizerCacheManager cache = new StubCacheManager(Collections.emptyMap(), roles);

    Set<String> claims = new HashSet<>(Arrays.asList("r2", "nope"));
    Set<String> out = RoleProviderUtil.getRolesByClaimValue("authz", claims, new HashSet<>(), cache);
    assertEquals(new HashSet<>(Collections.singletonList("r2")), out);
  }

  @Test
  public void getRolesByClaimValuesThrowsWhenRoleMapNull()
  {
    BasicAuthorizerCacheManager cache = new StubCacheManager(Collections.emptyMap(), null);
    assertTrue(RoleProviderUtil.getRolesByClaimValue("authz", new HashSet<>(Collections.singletonList("r2")),
                                                     new HashSet<>(), cache
    ).isEmpty());
  }
}
