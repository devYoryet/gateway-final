package com.zosh.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class CognitoAuthenticationFilter implements WebFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WebClient webClient;

    public CognitoAuthenticationFilter(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        String requestPath = exchange.getRequest().getURI().getPath();

        System.out.println("🔍 CognitoAuthenticationFilter - Processing: " + requestPath);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                if (isCognitoToken(token)) {
                    return processCognitoTokenWithSecurity(exchange, chain, token, authHeader);
                } else {
                    System.out.println("⚠️ Token no es de Cognito, pasando sin autenticación");
                    return chain.filter(exchange);
                }
            } catch (Exception e) {
                System.err.println("❌ Error procesando token: " + e.getMessage());
                return chain.filter(exchange);
            }
        }

        System.out.println("⚠️ Sin Authorization header");
        return chain.filter(exchange);
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

    private Mono<Void> processCognitoTokenWithSecurity(
            ServerWebExchange exchange, WebFilterChain chain, String token, String authHeader) {

        try {
            // 1. Extraer información del token
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

            // 2. Consultar BD para obtener el rol del usuario
            return getUserRoleFromDB(cognitoSub, email)
                    .flatMap(userRole -> {
                        System.out.println("✅ Rol obtenido de BD: " + userRole);

                        // 3. Crear Authentication con el rol de la BD
                        List<GrantedAuthority> authorities = new ArrayList<>();
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + userRole.replace("ROLE_", "")));

                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                email, null, authorities);

                        // 4. Añadir headers para microservicios
                        var modifiedRequest = exchange.getRequest().mutate()
                                .header("X-Cognito-Sub", cognitoSub)
                                .header("X-User-Email", email)
                                .header("X-User-Username", username)
                                .header("X-User-Role", userRole)
                                .header("X-Auth-Source", "Cognito")
                                .header("Authorization", authHeader)
                                .build();

                        var modifiedExchange = exchange.mutate().request(modifiedRequest).build();

                        // 5. Establecer contexto de seguridad y continuar
                        return chain.filter(modifiedExchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                    })
                    .onErrorResume(error -> {
                        System.err.println("❌ Error consultando BD: " + error.getMessage());
                        return chain.filter(exchange);
                    });

        } catch (Exception e) {
            System.err.println("❌ Error procesando token: " + e.getMessage());
            return chain.filter(exchange);
        }
    }

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

                    return webClient.get()
                            .uri("http://USER/api/users/by-email/" + email)
                            .retrieve()
                            .bodyToMono(UserResponse.class)
                            .map(user -> {
                                System.out.println("✅ Usuario encontrado por email: " + user.getRole());
                                return user.getRole();
                            })
                            .onErrorReturn("CUSTOMER"); // Rol por defecto
                });
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
}