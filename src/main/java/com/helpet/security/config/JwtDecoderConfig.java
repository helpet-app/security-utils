package com.helpet.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.interfaces.RSAPublicKey;

@AutoConfiguration
public class JwtDecoderConfig {
    @Value("${auth.keys.access-token-public-key}")
    private RSAPublicKey tokenPublicKey;

    @ConditionalOnMissingBean
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(tokenPublicKey).build();
    }
}
