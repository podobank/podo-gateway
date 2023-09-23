package com.yongy.podogateway.security.filter;

import com.yongy.podogateway.security.service.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter implements WebFilter {

    private final JwtProvider jwtProvider;

    // 헤더 내부에서 JWT 용으로 사용 할 Key
    // 보통 Authorization
    public static final String HEADER_KEY = "Authorization";

    // 인증 타입
    // JWT는 Bearer 토큰의 일종
    public static final String PREFIX = "Bearer ";

    private String extractTokenFromRequest(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HEADER_KEY);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(PREFIX)) {
            return bearerToken.substring(PREFIX.length());
        }
        return null;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request =  exchange.getRequest();

        log.info(request.getPath() + " " + request.getMethod());

        String token = extractTokenFromRequest(request);

        Authentication authentication = null;
        if (StringUtils.hasText(token)) {
            // 토큰이 있는 경우
            if (jwtProvider.verifyToken(token)) { // 권한 확인
                authentication = jwtProvider.getAuthentication(token); // 인증 정보와 권한 가져오기
                SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContextHolder : spring security 인메모리 세션저장소
            }
        }

        if(authentication != null) {
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        } else {
            return chain.filter(exchange);
        }
    }
}
