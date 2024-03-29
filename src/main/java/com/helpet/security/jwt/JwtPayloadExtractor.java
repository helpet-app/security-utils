package com.helpet.security.jwt;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.UUID;

public class JwtPayloadExtractor {
    private static final String USERNAME_CLAIM_KEY = "username";

    private static final String ROLES_CLAIM_KEY = "roles";

    private static final String FIRST_NAME_CLAIM_KEY = "firstName";

    private static final String MIDDLE_NAME_CLAIM_KEY = "middleName";

    private static final String LAST_NAME_CLAIM_KEY = "lastName";

    private static final String EMAIL_CLAIM_KEY = "email";

    private static final String EMAIL_VERIFIED_CLAIM_KEY = "emailVerified";

    private static final String SESSION_ID_CLAIM_KEY = "sid";

    private JwtPayloadExtractor() {}

    public static UUID extractId(Jwt jwt) {
        return UUID.fromString(jwt.getId());
    }

    public static UUID extractSubject(Jwt jwt) {
        return UUID.fromString(jwt.getSubject());
    }

    public static UUID extractSessionId(Jwt jwt) {
        return UUID.fromString(jwt.getClaimAsString(SESSION_ID_CLAIM_KEY));
    }

    public static String extractUsername(Jwt jwt) {
        return jwt.getClaimAsString(USERNAME_CLAIM_KEY);
    }

    public static List<String> extractRoles(Jwt jwt) {
        return jwt.getClaimAsStringList(ROLES_CLAIM_KEY);
    }

    public static String extractFirstName(Jwt jwt) {
        return jwt.getClaimAsString(FIRST_NAME_CLAIM_KEY);
    }

    public static String extractMiddleName(Jwt jwt) {
        return jwt.getClaimAsString(MIDDLE_NAME_CLAIM_KEY);
    }

    public static String extractLastName(Jwt jwt) {
        return jwt.getClaimAsString(LAST_NAME_CLAIM_KEY);
    }

    public static String extractEmail(Jwt jwt) {
        return jwt.getClaimAsString(EMAIL_CLAIM_KEY);
    }

    public static Boolean extractEmailVerified(Jwt jwt) {
        return jwt.getClaimAsBoolean(EMAIL_VERIFIED_CLAIM_KEY);
    }
}
