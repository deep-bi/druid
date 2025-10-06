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

import com.fasterxml.jackson.annotation.JacksonInject;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import net.minidev.json.JSONArray;
import org.apache.druid.server.security.Access;
import org.apache.druid.server.security.Action;
import org.apache.druid.server.security.AuthenticationResult;
import org.apache.druid.server.security.Authorizer;
import org.apache.druid.server.security.Resource;
import org.apache.druid.server.security.ResourceAction;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@JsonTypeName("pac4j")
public class Pac4jAuthorizer implements Authorizer
{

  private final OIDCConfig oidcConfig;
  private final PermissionsCollector permissionsCollector;

  @JsonCreator
  public Pac4jAuthorizer(
      @JacksonInject OIDCConfig oidcConfig,
      @JacksonInject PermissionsCollector permissionsCollector
  )
  {
    this.oidcConfig = oidcConfig;
    this.permissionsCollector = permissionsCollector;
  }

  @Override
  public Access authorize(AuthenticationResult authenticationResult, Resource resource, Action action)
  {
    if (authenticationResult == null) {
      return deny("AuthenticationResult is null, denying access to resource");
    }
    Map<String, Object> authenticationContext = authenticationResult.getContext();

    if (authenticationContext == null) {
      return deny("AuthenticationContext is null, denying access to resource");
    }

    final String groupClaimName = oidcConfig.getOidcClaim();
    if (groupClaimName == null || groupClaimName.isBlank()) {
      // no group claim name provided in config, always allow
      return allow();
    }

    Object groupClaim = authenticationContext.get(oidcConfig.getOidcClaim());

    if (groupClaim == null) {
      return deny("Authentication context has no group claims, denying access");
    }

    Set<String> groups = normalizeGroups(groupClaim);
    if (groups.isEmpty()) {
      return deny("Group set is empty, denying access");
    }

    List<PermissionDto> perms;
    try {
      perms = permissionsCollector.collect(groups);
    }
    catch (Exception e) {
      return deny("Exception while collecting permissions, denying access: " + e.getMessage());
    }
    if (perms == null || perms.isEmpty()) {
      return deny("No permissions resolved for groups, denying access");
    }

    for (PermissionDto p : perms) {
      if (permissionCheck(resource, action, p)) {
        return allow();
      }
    }

    return deny("No matching permission found, denying access");

  }

  private Access allow()
  {
    return Access.allow();
  }

  private Access deny(final String reason)
  {
    return Access.deny(reason);
  }

  private Set<String> normalizeGroups(Object value)
  {
    final Set<String> out = new HashSet<>();

    if (value == null) {
      return out;
    }

    if (value instanceof JSONArray) {
      final JSONArray arr = (JSONArray) value;
      for (Object o : arr) {
        if (o != null) {
          final String s = o.toString().trim();
          if (!s.isEmpty()) {
            out.add(s);
          }
        }
      }
      return out;
    }

    if (value instanceof Collection) {
      final Collection<?> c = (Collection<?>) value;
      for (Object o : c) {
        if (o != null) {
          final String s = o.toString().trim();
          if (!s.isEmpty()) {
            out.add(s);
          }
        }
      }
      return out;
    }

    if (value.getClass().isArray()) {
      final int n = Array.getLength(value);
      for (int i = 0; i < n; i++) {
        final Object o = Array.get(value, i);
        if (o != null) {
          final String s = o.toString().trim();
          if (!s.isEmpty()) {
            out.add(s);
          }
        }
      }
      return out;
    }

    final String s = value.toString().trim();
    if (!s.isEmpty()) {
      final String[] parts = s.split("[,;\\s]+");
      for (String part : parts) {
        final String p = part.trim();
        if (!p.isEmpty()) {
          out.add(p);
        }
      }
    }

    return out;
  }

  private boolean permissionCheck(Resource resource, Action action, PermissionDto permission)
  {
    if (permission == null) {
      return false;
    }
    if (resource == null) {
      return false;
    }
    if (action == null) {
      return false;
    }

    ResourceAction ra = permission.getResourceAction();
    if (ra == null) {
      return false;
    }

    if (ra.getAction() != action) {
      return false;
    }

    Resource pr = ra.getResource();
    if (pr == null) {
      return false;
    }
    if (!Objects.equals(pr.getType(), resource.getType())) {
      return false;
    }

    if (resource.getName() == null) {
      return false;
    }

    Pattern pattern = permission.getResourceNamePattern();
    if (pattern == null) {
      return false;
    }
    Matcher m = pattern.matcher(resource.getName());
    return m.matches();
  }
}
