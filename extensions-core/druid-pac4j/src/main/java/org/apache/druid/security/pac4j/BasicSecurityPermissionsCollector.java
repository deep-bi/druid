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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.druid.java.util.common.logger.Logger;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class BasicSecurityPermissionsCollector implements PermissionsCollector
{
  private final HttpClient httpClient;
  private final ObjectMapper mapper;
  private final OIDCConfig oidcConfig;
  private final String authHeader;
  private static final Logger logger = new Logger(BasicSecurityPermissionsCollector.class);

  @Inject
  public BasicSecurityPermissionsCollector(
      @JacksonInject HttpClient httpClient,
      @JacksonInject OIDCConfig oidcConfig,
      @JacksonInject ObjectMapper objectMapper
  )
  {
    this.httpClient = httpClient;
    this.oidcConfig = oidcConfig;
    this.mapper = objectMapper;
    String user = oidcConfig.getDruidUsername();
    String pass = oidcConfig.getDruidPassword().getPassword();
    String token = Base64.getEncoder().encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
    this.authHeader = "Basic " + token;
  }

  @Override
  public List<PermissionDto> collect(Set<String> groups)
  {
    logger.debug("Getting permissions for groups %s", groups);
    if (groups == null || groups.isEmpty()) {
      return Collections.emptyList();
    }
    try {
      Set<String> roles = new HashSet<>();
      for (String group : groups) {
        if (group == null || group.trim().isEmpty()) {
          continue;
        }
        roles.addAll(fetchRolesForGroup(group));
      }
      if (roles.isEmpty()) {
        return Collections.emptyList();
      }

      List<PermissionDto> out = new ArrayList<>();
      for (String role : roles) {
        if (role == null || role.trim().isEmpty()) {
          continue;
        }
        out.addAll(fetchPermissionsForRole(role));
      }
      return out;
    }
    catch (Exception e) {
      logger.error(e, "Permission collection failed");
      return Collections.emptyList();
    }
  }


  private Collection<String> fetchRolesForGroup(String group) throws Exception
  {
    String url = oidcConfig.getDruidBaseUrl()
                 + "/proxy/coordinator/druid-ext/basic-security/authorization/db/basic/groupMappings/" + group;

    HttpGet req = new HttpGet(url);
    req.setHeader("Authorization", authHeader);
    req.setHeader("Accept", "application/json");

    ResponseHandler<Collection<String>> rh = resp -> {
      int code = resp.getStatusLine().getStatusCode();
      if (code != 200) {
        logger.warn("Non-200 response [%d] from basic security group mapping API for group %s", code, group);
        return Collections.emptyList();
      }
      JsonNode root = mapper.readTree(resp.getEntity().getContent());
      JsonNode roles = root.get("roles");
      if (roles == null || !roles.isArray()) {
        logger.warn("No roles array in response from basic security group mapping API for group %s", group);
        return Collections.emptyList();
      }
      List<String> out = new ArrayList<>();
      Iterator<JsonNode> it = roles.elements();
      while (it.hasNext()) {
        JsonNode n = it.next();
        if (n != null) {
          String s = n.asText(null);
          if (s != null && !s.trim().isEmpty()) {
            out.add(s.trim());
          }
        }
      }
      return out;
    };

    return httpClient.execute(req, rh);
  }

  private Collection<PermissionDto> fetchPermissionsForRole(String role)
      throws Exception
  {
    String url = oidcConfig.getDruidBaseUrl()
                 + "/proxy/coordinator/druid-ext/basic-security/authorization/db/basic/roles/" + role + "?full";

    HttpGet req = new HttpGet(url);
    req.setHeader("Authorization", authHeader);
    req.setHeader("Accept", "application/json");

    ResponseHandler<Collection<PermissionDto>> rh = resp -> {
      int code = resp.getStatusLine().getStatusCode();
      if (code != 200) {
        logger.warn("Non-200 response [%d] from basic security roles API for role %s", code, role);
        return Collections.emptyList();
      }
      JsonNode root = mapper.readTree(resp.getEntity().getContent());
      JsonNode perms = root.get("permissions");
      if (perms == null || !perms.isArray()) {
        logger.warn("No permissions array in response from basic security roles API for role %s", role);
        return Collections.emptyList();
      }
      List<PermissionDto> out = new ArrayList<>();
      Iterator<JsonNode> it = perms.elements();
      while (it.hasNext()) {
        JsonNode p = it.next();
        if (p != null && p.isObject()) {
          PermissionDto bp = mapper.treeToValue(p, PermissionDto.class);
          if (bp != null) {
            out.add(bp);
          }
        }
      }
      return out;
    };

    return httpClient.execute(req, rh);
  }
}
