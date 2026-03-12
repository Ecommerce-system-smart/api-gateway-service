package com.example.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

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

    /**
     * Tự định nghĩa Bean JwtDecoder để giải quyết triệt để lỗi bất đồng Issuer trên K8s
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        // 1. Chỉ định đường dẫn đi tải Public Key (Dùng mạng nội bộ K8s)
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();

        // 2. Chỉ định tên Issuer bắt buộc phải có trong Token (Khớp với Postman)
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);

        // 3. Gắn bộ kiểm tra vào Decoder
        jwtDecoder.setJwtValidator(withIssuer);

        return jwtDecoder;
    }
}