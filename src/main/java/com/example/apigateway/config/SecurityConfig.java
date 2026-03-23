package com.example.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    // Lấy giá trị issuer-uri từ application.yml (localhost:31000...)
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    // Lấy giá trị jwk-set-uri từ application.yml (keycloak:8180...)
    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    // ... (Giữ nguyên Bean springSecurityFilterChain cũ của bạn ở đây) ...

    // 1. Cấu hình Filter CORS toàn cục cho WebFlux
    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:5173")); // Cho phép React
        corsConfig.setMaxAge(3600L); // Cache preflight request trong 1 giờ
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfig.setAllowedHeaders(Arrays.asList("*"));
        corsConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }

    // 2. Cập nhật lại Security Filter Chain
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> {}) // Kích hoạt CORS đã cấu hình ở Bean trên
                .authorizeExchange(exchanges -> exchanges
                        // CHO PHÉP TẤT CẢ CÁC REQUEST OPTIONS ĐI QUA MÀ KHÔNG CẦN TOKEN
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        // Cho phép gọi API đăng ký không cần Token
                        .pathMatchers("/api/users/**").permitAll()
                        // Cho phép gọi các API public nếu có (ví dụ: xem danh sách sản phẩm)
                        // .pathMatchers(HttpMethod.GET, "/api/products/**").permitAll()
                        // Các request khác vẫn phải có Token hợp lệ
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder()))
                );
        return http.build();
    }

    // Bean jwtDecoder của bạn giữ nguyên không thay đổi
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        jwtDecoder.setJwtValidator(withIssuer);
        return jwtDecoder;
    }
}