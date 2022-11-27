package com.helpet.security.jwt;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private static final String USERNAME_CLAIM_KEY = "username";

    private final Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter;

    public KeycloakJwtAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter) {
        this.grantedAuthoritiesConverter = grantedAuthoritiesConverter;
    }

    @Override
    public JwtAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = grantedAuthoritiesConverter.convert(jwt);
        String username = extractUsername(jwt);

        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    private String extractUsername(Jwt jwt) {
        if (jwt.hasClaim(USERNAME_CLAIM_KEY)) {
            return jwt.getClaimAsString(USERNAME_CLAIM_KEY);
        }

        return jwt.getSubject();
    }
}
