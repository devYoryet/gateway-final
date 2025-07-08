// =============================================================================
// GATEWAY - UserContextFilter CORREGIDO para email vacío
// src/main/java/com/zosh/config/UserContextFilter.java
// =============================================================================
package com.zosh.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Base64;

@Component
public class UserContextFilter extends AbstractGatewayFilterFactory<UserContextFilter.Config> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public UserContextFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

            System.out.println("🔍 UserContextFilter - Processing request: " + exchange.getRequest().getURI());

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                try {
                    if (isCognitoToken(token)) {
                        return processCognitoToken(exchange, chain, token);
                    } else {
                        System.out.println("⚠️ Token no es de Cognito, procesando como JWT tradicional");
                        return chain.filter(exchange);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Error procesando token: " + e.getMessage());
                    return chain.filter(exchange);
                }
            }

            System.out.println("⚠️ Sin Authorization header");
            return chain.filter(exchange);
        };
    }

    private boolean isCognitoToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2)
                return false;

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            return payload.contains("cognito") || payload.contains("amazonaws");
        } catch (Exception e) {
            return false;
        }
    }

    private Mono<Void> processCognitoToken(
            org.springframework.web.server.ServerWebExchange exchange,
            org.springframework.cloud.gateway.filter.GatewayFilterChain chain,
            String token) {

        try {
            // Decodificar payload del JWT
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            JsonNode claims = objectMapper.readTree(payload);

            String cognitoUserId = claims.get("sub").asText();

            // 🚀 EXTRAER EMAIL CON MÚLTIPLES INTENTOS
            String email = extractEmail(claims);

            // 🚀 EXTRAER ROL CON MÚLTIPLES INTENTOS
            String customRole = extractRole(claims);

            // 🚀 GENERAR USERNAME DESDE EMAIL O SUB
            String username = generateUsername(email, cognitoUserId);

            System.out.println("✅ Cognito token procesado:");
            System.out.println("   Sub: " + cognitoUserId);
            System.out.println("   Email: " + email);
            System.out.println("   Username: " + username);
            System.out.println("   Role: " + customRole);

            // 🚀 CREAR HEADERS COMPLETOS
            var mutatedRequest = exchange.getRequest().mutate()
                    .header("X-Cognito-Sub", cognitoUserId)
                    .header("X-User-Email", email)
                    .header("X-User-Username", username)
                    .header("X-User-Role", customRole)
                    .header("X-Gateway-Filter", "UserContextFilter")
                    .header("X-Auth-Source", "Cognito")
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (Exception e) {
            System.err.println("❌ Error procesando Cognito token: " + e.getMessage());
            e.printStackTrace();
            return chain.filter(exchange);
        }
    }

    private String extractEmail(JsonNode claims) {
        // Intentar múltiples campos para obtener email
        String email = null;

        // Intento 1: Campo "email" estándar
        if (claims.has("email") && !claims.get("email").isNull()) {
            email = claims.get("email").asText();
        }

        // Intento 2: Campo "email_verified" a veces contiene el email
        if ((email == null || email.isEmpty()) && claims.has("username")) {
            String username = claims.get("username").asText();
            if (username.contains("@")) {
                email = username;
            }
        }

        // Intento 3: Campo "preferred_username"
        if ((email == null || email.isEmpty()) && claims.has("preferred_username")) {
            String prefUsername = claims.get("preferred_username").asText();
            if (prefUsername.contains("@")) {
                email = prefUsername;
            }
        }

        // Intento 4: Usar sub como base para email temporal
        if (email == null || email.isEmpty()) {
            String sub = claims.get("sub").asText();
            email = sub.substring(0, 8) + "@cognito.generated";
            System.out.println("⚠️ Email no encontrado, generando: " + email);
        }

        return email;
    }

    private String extractRole(JsonNode claims) {
        String role = "SALON_OWNER"; // Por defecto

        // Intento 1: custom:role
        if (claims.has("custom:role") && !claims.get("custom:role").isNull()) {
            role = claims.get("custom:role").asText();
        }

        // Intento 2: cognito:groups
        else if (claims.has("cognito:groups")) {
            JsonNode groups = claims.get("cognito:groups");
            if (groups.isArray() && groups.size() > 0) {
                role = groups.get(0).asText();
            }
        }

        // Intento 3: groups
        else if (claims.has("groups")) {
            JsonNode groups = claims.get("groups");
            if (groups.isArray() && groups.size() > 0) {
                role = groups.get(0).asText();
            }
        }

        // Para el caso específico: si viene de become-partner, debería ser SALON_OWNER
        // Podríamos inferirlo del contexto o URL

        return role.toUpperCase();
    }

    private String generateUsername(String email, String cognitoUserId) {
        if (email != null && !email.isEmpty() && !email.contains("@cognito.generated")) {
            return email;
        } else {
            return "user_" + cognitoUserId.substring(0, 8);
        }
    }

    public static class Config {
        // Configuración del filtro
    }
}