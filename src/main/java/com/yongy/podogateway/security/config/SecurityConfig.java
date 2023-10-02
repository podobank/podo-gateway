package com.yongy.podogateway.security.config;

import com.yongy.podogateway.security.filter.JwtAuthFilter;
import com.yongy.podogateway.security.service.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtProvider jwtProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception {
        // jwt 로그인
        http.cors().and()
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .authorizeExchange()

                .pathMatchers("api/v1/user/admin/**").hasRole("ADMIN")
                .pathMatchers("/api/v1/account/admin/**").hasRole("ADMIN")
                .pathMatchers("/api/v1/fintech/admin/**").hasRole("ADMIN")

                .pathMatchers("/api/v1/auth/**").permitAll()
                .pathMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                .pathMatchers("/api/v1/account/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                .pathMatchers("/api/v1/fintech/**").hasAnyRole("MANAGER", "ADMIN")

                .anyExchange().denyAll()
                .and()
                .addFilterAt(new JwtAuthFilter(jwtProvider), SecurityWebFiltersOrder.AUTHENTICATION)
                .logout().disable();
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOriginPattern("*"); // 모든 요청을 허용
        configuration.addAllowedMethod("*"); // 모든 메소드를 허용
        configuration.addAllowedHeader("*"); // 모든 헤더를 허용
        configuration.setAllowCredentials(true); // 쿠키 인증 허용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
