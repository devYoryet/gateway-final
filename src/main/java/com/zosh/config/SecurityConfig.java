package com.zosh.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

        @Autowired
        private WebClient.Builder webClientBuilder;

        @Bean
        public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity serverHttpSecurity) {
                System.out.println(
                                "🔧 GATEWAY SECURITY - UserContextFilter maneja validación, permitiendo todo temporalmente");

                serverHttpSecurity
                                .authorizeExchange(exchanges -> exchanges
                                                // 🚀 TEMPORAL: Permitir todo para que UserContextFilter maneje la
                                                // validación
                                                .anyExchange().permitAll())
                                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

                System.out.println("✅ GATEWAY SECURITY - UserContextFilter habilitado para validar roles desde BD");
                return serverHttpSecurity.build();
        }

        /**
         * 🌐 CORS Configuration
         */
        private CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(Arrays.asList(
                                "http://localhost:3000",
                                "https://salon-booking-three.vercel.app",
                                "https://urban-glow.vercel.app",
                                "https://front-final-nine.vercel.app"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        /**
         * 🔧 UserContextFilter Bean
         */
        @Bean
        public UserContextFilter userContextFilter() {
                return new UserContextFilter(webClientBuilder);
        }
}