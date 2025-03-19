package com.new_spring_security.config.security.jwt;

import com.new_spring_security.comm.ErrorCode;
import com.new_spring_security.config.security.auth.PrincipalDetailsService;
import com.new_spring_security.domain.user.etc.UserRoles;
import com.new_spring_security.handler.exception.CustomApiException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.codec.DecodingException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

/**
 * @class   JwtTokenProvider
 * @brief   JWT 관련 Component(생성, 인증, 검증)
 * @details JWT 관련 기능을 담당한다
 */
@Component
public class JwtTokenProvider {

    private final PrincipalDetailsService principalDetailsService;

    private Key key;

    @Value("${app.jwt.secret}") private String JWT_SECRET;
    @Value("${app.jwt.prefix}") private String PREFIX;
    @Value("${app.jwt.expirationMs.accessToken}")  private Long ACCESS_TOKEN_EXPIRATION_MS;
    @Value("${app.jwt.expirationMs.refreshToken}") private Long REFRESH_TOKEN_EXPIRATION_MS;
    @Value("${app.jwt.tokenHeader.accessToken}")   private String ACCESS_TOKEN_HEADER;
    @Value("${app.jwt.tokenHeader.refreshToken}")  private String REFRESH_TOKEN_HEADER;


    public JwtTokenProvider(PrincipalDetailsService principalDetailsService) {
        this.principalDetailsService = principalDetailsService;
    }

    /**
     * @PostConstruct: 의존성 주입이 끝난 후 실행되는 메서드를 지정하는 어노테이션
     * init 역할: jwt 서명에 사용할 Key 객체 초기화
     * 이유: 토큰을 안전하게 서명하고 검증하게 하기 위함
     */
    @PostConstruct
    protected void init() {
        this.key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Access Token 생성
     */
    public String createAccessToken(String username, UserRoles role) {
        return createToken(username, role, ACCESS_TOKEN_EXPIRATION_MS);
    }

    /**
     * Refresh Token 생성 (권한 정보 없이 생성)
     */
    public String createRefreshToken(String username) {
        return createToken(username, null, REFRESH_TOKEN_EXPIRATION_MS);
    }

    /**
     * JWT 토큰 생성 (Access & Refresh 공통)
     */
    private String createToken(String username, UserRoles roles, long validity) {
        Claims claims = Jwts.claims().setSubject(username);

        if (roles != null) {
            claims.put("roles", roles);
        }

        Date now = new Date();
        Date expiration = new Date(now.getTime() + validity);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * JWT 토큰에서 사용자 이름(아이디) 추출
     */
    public String getEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * JWT 토큰에서 권한 정보 추출 (Access Token용)
     */
    public UserRoles getRoles(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return UserRoles.getRole(claims.get("roles").toString());
    }

    /**
     * JWT 토큰에서 Bearer replace
     */
    public String replaceToken(String token) {

        if (token == null)
            return null;
        else if (token.contains("Bearer"))
            token = token.replace("Bearer ", "");
        else
            throw new DecodingException("");

        return token;
    }

    // Claims > Authentication 반환
    protected Authentication getAuthentication(Claims claims) {
        UserDetails userDetails = principalDetailsService.loadUserByUsername(claims.get("email", String.class));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * JWT 토큰에서 claims 정보 추출 (Access Token용)
     */
    public Claims getClaimsByToken(String token) {

        if (token == null)
            return null;
        else if (token.contains("Bearer"))
            token = token.replace("Bearer ", "");
        else
            throw new DecodingException("");


        SecretKey secretKey = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    /**
     * JWT 토큰의 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);

            return !claims.getBody().getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            System.out.println(("JWT 토큰이 만료되었습니다."));
        } catch (MalformedJwtException e) {
            System.out.println(("JWT 토큰이 올바르지 않습니다."));
        } catch (SecurityException | SignatureException e) {
            System.out.println(("JWT 서명이 유효하지 않습니다."));
        } catch (IllegalArgumentException e) {
            System.out.println(("JWT 토큰이 비어 있거나 올바르지 않습니다."));
        } catch (JwtException e) {
            System.out.println(("JWT 토큰이 유효하지 않습니다."));
        }
        return false;
    }

    /**
     * @brief   accessToken Header에 설정
     * @param   response
     * @param   accessToken
     */
    public void setAccessTokenToHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(ACCESS_TOKEN_HEADER,PREFIX + accessToken);
    }

    /**
     * @brief   refreshToken Header에 설정
     * @param   response
     * @param   refreshToken
     */
    public void setRefreshTokenToHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(REFRESH_TOKEN_HEADER, PREFIX + refreshToken);
    }
}
