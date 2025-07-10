// =============================================================================
// GATEWAY HÍBRIDO - UserContextFilter que funciona con TODOS los microservicios
// Sin necesidad de cambiar nada más
// =============================================================================
package com.zosh.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Base64;

@Component
public class UserContextFilter extends AbstractGatewayFilterFactory<UserContextFilter.Config> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WebClient webClient;

    @Autowired
    public UserContextFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            String requestPath = exchange.getRequest().getURI().getPath();

            System.out.println("🔍 HYBRID GATEWAY - Processing: " + requestPath);
            System.out.println("🔍 Auth Header: " + (authHeader != null ? "Present" : "Missing"));

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                try {
                    if (isCognitoToken(token)) {
                        return processCognitoTokenHybrid(exchange, chain, token, authHeader);
                    } else {
                        System.out.println("⚠️ Token no es de Cognito, pasando sin modificar");
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

    private Mono<Void> processCognitoTokenHybrid(
            org.springframework.web.server.ServerWebExchange exchange,
            org.springframework.cloud.gateway.filter.GatewayFilterChain chain,
            String token,
            String originalAuthHeader) {

        try {
            // 1. Extraer información del token Cognito
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return chain.filter(exchange);
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode claims = objectMapper.readTree(payload);

            String cognitoSub = claims.get("sub").asText();
            String email = claims.has("email") ? claims.get("email").asText() : "";
            String username = claims.has("preferred_username") ? claims.get("preferred_username").asText()
                    : (claims.has("username") ? claims.get("username").asText() : email);

            System.out.println("🔍 Datos extraídos de Cognito:");
            System.out.println("   Sub: " + cognitoSub);
            System.out.println("   Email: " + email);
            System.out.println("   Username: " + username);

            // 2. Consultar BD para obtener rol del usuario
            return getUserRoleFromDB(cognitoSub, email)
                    .flatMap(userRole -> {
                        System.out.println("✅ Rol obtenido de BD: " + userRole);

                        // 3. Validar acceso según rol y ruta
                        String requestPath = exchange.getRequest().getURI().getPath();
                        if (!hasAccess(userRole, requestPath)) {
                            System.out.println("❌ Acceso denegado - Rol: " + userRole + ", Ruta: " + requestPath);
                            return unauthorizedResponse(exchange);
                        }

                        // 4. 🚀 CLAVE: Añadir AMBOS - headers Y JWT original
                        var modifiedRequest = exchange.getRequest().mutate()
                                // ✅ Headers para microservicios ya modificados
                                .header("X-Cognito-Sub", cognitoSub)
                                .header("X-User-Email", email)
                                .header("X-User-Username", username)
                                .header("X-User-Role", userRole)
                                .header("X-Auth-Source", "Cognito")

                                // ✅ JWT original para microservicios no modificados
                                .header("Authorization", originalAuthHeader)
                                .build();

                        var modifiedExchange = exchange.mutate()
                                .request(modifiedRequest)
                                .build();

                        System.out.println("✅ HYBRID MODE: Headers Y JWT enviados");
                        return chain.filter(modifiedExchange);
                    })
                    .onErrorResume(error -> {
                        System.err.println("❌ Error consultando BD: " + error.getMessage());
                        // Si falla la consulta, enviar request original
                        return chain.filter(exchange);
                    });

        } catch (Exception e) {
            System.err.println("❌ Error procesando token: " + e.getMessage());
            return chain.filter(exchange);
        }
    }

    // 🚀 MÉTODO PARA CONSULTAR BD
    private Mono<String> getUserRoleFromDB(String cognitoSub, String email) {
        System.out.println("🔍 Consultando BD para usuario: " + email);

        return webClient.get()
                .uri("http://USER/api/users/by-cognito-id/" + cognitoSub)
                .retrieve()
                .bodyToMono(UserResponse.class)
                .map(user -> {
                    System.out.println("✅ Usuario encontrado en BD: " + user.getRole());
                    return user.getRole();
                })
                .onErrorResume(error -> {
                    System.out.println("⚠️ Usuario no encontrado por Cognito ID, intentando por email");

                    // Fallback: buscar por email
                    return webClient.get()
                            .uri("http://USER/api/users/by-email/" + email)
                            .retrieve()
                            .bodyToMono(UserResponse.class)
                            .map(user -> {
                                System.out.println("✅ Usuario encontrado por email: " + user.getRole());
                                return user.getRole();
                            })
                            .onErrorReturn("CUSTOMER"); // Rol por defecto si no encuentra
                });
    }

    // 🚀 VALIDACIÓN DE ACCESO MEJORADA - MÁS ESPECÍFICA
    private boolean hasAccess(String userRole, String requestPath) {
        System.out.println("🔍 Validando acceso - Rol: " + userRole + ", Ruta: " + requestPath);

        // Normalizar rol (quitar ROLE_ prefix si existe)
        String normalizedRole = userRole.replace("ROLE_", "");

        // 🚀 RUTAS QUE REQUIEREN ADMIN
        if (requestPath.startsWith("/admin") ||
                requestPath.startsWith("/api/admin") ||
                requestPath.contains("/admin/")) {
            boolean hasAccess = "ADMIN".equals(normalizedRole);
            System.out.println("🔍 Ruta ADMIN - Acceso: " + hasAccess);
            return hasAccess;
        }

        // 🚀 RUTAS QUE REQUIEREN SALON_OWNER
        if (requestPath.contains("salon-owner") ||
                requestPath.contains("/owner") ||
                requestPath.contains("/chart") ||
                requestPath.equals("/api/salons/owner") ||
                requestPath.startsWith("/api/service-offering/salon-owner") ||
                requestPath.startsWith("/api/categories/salon-owner") ||
                requestPath.startsWith("/api/bookings/chart")) {
            boolean hasAccess = "SALON_OWNER".equals(normalizedRole) || "ADMIN".equals(normalizedRole);
            System.out.println("🔍 Ruta SALON_OWNER - Acceso: " + hasAccess);
            return hasAccess;
        }

        // 🚀 RUTAS QUE REQUIEREN CUSTOMER o superior
        if (requestPath.startsWith("/api/bookings") && !requestPath.contains("/chart")) {
            boolean hasAccess = "CUSTOMER".equals(normalizedRole) ||
                    "SALON_OWNER".equals(normalizedRole) ||
                    "ADMIN".equals(normalizedRole);
            System.out.println("🔍 Ruta CUSTOMER - Acceso: " + hasAccess);
            return hasAccess;
        }

        // 🚀 RUTAS PÚBLICAS (cualquier usuario autenticado)
        if (requestPath.contains("/api/salons") ||
                requestPath.contains("/api/service-offering") ||
                requestPath.contains("/api/categories") ||
                requestPath.contains("/api/reviews") ||
                requestPath.contains("/api/users/profile") ||
                requestPath.contains("/api/notifications") ||
                requestPath.contains("/api/payments")) {
            System.out.println("🔍 Ruta PÚBLICA - Acceso: true");
            return true;
        }

        // 🚀 POR DEFECTO PERMITIR (para desarrollo)
        System.out.println("🔍 Ruta NO ESPECÍFICA - Acceso: true (por defecto)");
        return true;
    }

    private Mono<Void> unauthorizedResponse(org.springframework.web.server.ServerWebExchange exchange) {
        System.out.println("❌ Enviando respuesta 401 - Unauthorized");
        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    // DTO para respuesta del microservicio User
    public static class UserResponse {
        private Long id;
        private String email;
        private String fullName;
        private String role;
        private String cognitoUserId;

        // Getters y setters
        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getFullName() {
            return fullName;
        }

        public void setFullName(String fullName) {
            this.fullName = fullName;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public String getCognitoUserId() {
            return cognitoUserId;
        }

        public void setCognitoUserId(String cognitoUserId) {
            this.cognitoUserId = cognitoUserId;
        }
    }

    public static class Config {
        // Configuración del filtro si es necesaria
    }
}