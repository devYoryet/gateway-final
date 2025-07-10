package com.zosh.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;

public class CognitoRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        // 🚀 EXTRAER ROL DE COGNITO (del custom:role)
        String customRole = jwt.getClaimAsString("custom:role");
        if (customRole != null && !customRole.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + customRole.toUpperCase()));
            System.out.println("🔍 Rol extraído de Cognito: ROLE_" + customRole.toUpperCase());
        }

        // 🚀 EXTRAER GRUPOS DE COGNITO (si los usas)
        Object cognitoGroups = jwt.getClaim("cognito:groups");
        if (cognitoGroups instanceof java.util.List) {
            ((java.util.List<?>) cognitoGroups).forEach(group -> {
                if (group instanceof String) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + ((String) group).toUpperCase()));
                    System.out.println("🔍 Grupo extraído de Cognito: ROLE_" + ((String) group).toUpperCase());
                }
            });
        }

        // 🚀 FALLBACK: Si no hay roles en Cognito, consultar BD
        if (authorities.isEmpty()) {
            System.out.println("⚠️ No se encontraron roles en Cognito, se consultará BD");
            // Este caso se maneja en el CognitoAuthenticationFilter
        }

        return authorities;
    }
}