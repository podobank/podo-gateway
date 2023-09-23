package com.yongy.podogateway.security.service;

import com.yongy.podogateway.security.enums.Role;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtProvider {

    @Value("${jwt.secret-key}")
    private String SECRET_KEY;

    public boolean verifyToken(String token) {
        try {
            Claims claims = getClaims(token);

            // 토큰 만료시간 확인
            Date expiration = claims.getExpiration();
            return !expiration.before(new Date()); // 만료 시간이 지났으면(true) -> false 반환
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getUserEmailFromToken(String token) {
        return getClaims(token).getSubject();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        return new UsernamePasswordAuthenticationToken(getUserEmailFromToken(token), null, Collections.singleton(new SimpleGrantedAuthority(claims.get("role").toString())));
    }

    // 토큰에서 Claims 추출
    private Claims getClaims(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            log.info("만료된 토큰");
            throw new BadCredentialsException("만료된 토큰", e);
        } catch (MalformedJwtException e) {
            log.info("유효하지 않은 구성의 토큰");
            throw new BadCredentialsException("유효하지 않은 구성의 토큰", e);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 형식이나 구성의 토큰");
            throw new BadCredentialsException("지원되지 않는 형식이나 구성의 토큰", e);
        } catch (IllegalArgumentException e) {
            log.info("잘못된 입력값");
            throw new BadCredentialsException("잘못된 입력값", e);
        }
        return claims;
    }

    private void logGenerateToken(String email, Role role) {
        log.info("=====" + "\t" +
                "JWT 토큰 생성" + "\t" +
                "email: " + email + "\t" +
                "role: " + role + "\t" +
                "=====");
    }
}

