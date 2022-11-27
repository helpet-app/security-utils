package com.helpet.security.jwt;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;

public class KeycloakJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private static final String REALM_ACCESS_CLAIM_KEY = "realm_access";

    private static final String RESOURCE_ACCESS_CLAIM_KEY = "resource_access";

    private static final String SCOPE_CLAIM_KEY = "scope";

    private static final String ROLES_CLAIM_KEY = "roles";

    private static final String ROLE_PREFIX = "ROLE_";

    private static final String SCOPE_PREFIX = "SCOPE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        authorities.addAll(extractRealmRoles(jwt));
        authorities.addAll(extractResourceRoles(jwt));
        authorities.addAll(extractScopes(jwt));

        return authorities;
    }

    private Set<GrantedAuthority> extractRealmRoles(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        if (jwt.hasClaim(REALM_ACCESS_CLAIM_KEY)) {
            JSONObject realmAccess = new JSONObject(jwt.getClaimAsMap(REALM_ACCESS_CLAIM_KEY));
            if (realmAccess.has(ROLES_CLAIM_KEY)) {
                JSONArray realmRoles = realmAccess.getJSONArray(ROLES_CLAIM_KEY);
                for (Object realmRole : realmRoles) {
                    authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + normalizeRole(realmRole.toString())));
                }
            }
        }

        return authorities;
    }

    private Set<GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        if (jwt.hasClaim(RESOURCE_ACCESS_CLAIM_KEY)) {
            JSONObject resourceAccess = new JSONObject(jwt.getClaimAsMap(RESOURCE_ACCESS_CLAIM_KEY));
            resourceAccess.keys().forEachRemaining(resourceId -> {
                JSONArray resourceRoles = resourceAccess.getJSONObject(resourceId).getJSONArray(ROLES_CLAIM_KEY);
                for (Object resourceRole : resourceRoles) {
                    authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + normalizeRole(resourceRole.toString())));
                }
            });
        }

        return authorities;
    }

    private Set<GrantedAuthority> extractScopes(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        if (jwt.hasClaim(SCOPE_CLAIM_KEY)) {
            String scope = jwt.getClaimAsString(SCOPE_CLAIM_KEY);
            if (!scope.isBlank() && !scope.isEmpty()) {
                String[] scopes = scope.split("\\s");
                for (String scopeAuthority : scopes) {
                    authorities.add(new SimpleGrantedAuthority(SCOPE_PREFIX + normalizeRole(scopeAuthority)));
                }
            }
        }

        return authorities;
    }

    private String normalizeRole(String role) {
        return role.replace('-', '_').toUpperCase();
    }
}
