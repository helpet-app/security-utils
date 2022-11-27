package com.helpet.security.config;

import com.helpet.security.jwt.KeycloakJwtAuthenticationConverter;
import com.helpet.security.jwt.KeycloakJwtGrantedAuthoritiesConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableMethodSecurity(jsr250Enabled = true)
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
                .anyRequest()
                .authenticated()
        );

        http.csrf().disable();

        http.oauth2ResourceServer()
            .jwt()
            .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter());

        return http.build();
    }

    @Bean
    public KeycloakJwtGrantedAuthoritiesConverter keycloakJwtGrantedAuthoritiesConverter() {
        return new KeycloakJwtGrantedAuthoritiesConverter();
    }

    @Bean
    public KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter() {
        return new KeycloakJwtAuthenticationConverter(keycloakJwtGrantedAuthoritiesConverter());
    }
}
