package com.new_spring_security.config.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.new_spring_security.comm.Api;
import com.new_spring_security.comm.ErrorCode;
import com.new_spring_security.domain.user.dto.res.LoginResDto;
import com.new_spring_security.domain.user.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.codec.DecodingException;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @class   JwtOncePerRequestFilter
 * @brief   권합 삽입
 * @details 요청 당 한 번만 필터가 실행되도록 보장한다.
 * @author  최원호
 * @date    2023.05.02
 * version  1.0
 */
@RequiredArgsConstructor
public class JwtOncePerRequestFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;
    private final Environment env;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.contains("/swagger-ui") ||
                path.contains("/v3/api-docs") ||
                path.contains("/swagger-resources") ||
                path.contains("/webjars");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String accessToken = jwtTokenProvider.replaceToken(request.getHeader(env.getProperty("app.jwt.tokenHeader.accessToken")));
        String refreshToken = jwtTokenProvider.replaceToken(request.getHeader(env.getProperty("app.jwt.tokenHeader.refreshToken")));

        Claims claims = null;

        try {

            // AccessToken 만료 및 검증 true -> 만료 안됨
            if (jwtTokenProvider.validateToken(accessToken)) {
                // Access Token이 유효하면 그대로 인증 처리
                claims = jwtTokenProvider.getClaimsByToken(accessToken);

                // Access Token이 만료되었을 경우, Refresh Token으로 새로운 Access Token 발급
            } else if (jwtTokenProvider.validateToken(refreshToken)) {

                LoginResDto loginResDto = userService.getUserByRefreshToken(refreshToken);

                accessToken = jwtTokenProvider.createAccessToken(loginResDto.getEmail(), loginResDto.getRole());

                jwtTokenProvider.setAccessTokenToHeader(response, accessToken);

                claims = jwtTokenProvider.getClaimsByToken(accessToken);
            } else {
                sendErrorMessage(response, ErrorCode.JWT_IS_EXPIRED);
            }

            if (claims != null) {
                SecurityContextHolder.getContext().setAuthentication(jwtTokenProvider.getAuthentication(claims));
            }

            filterChain.doFilter(request, response);
        } catch (SecurityException e) {
            sendErrorMessage(response, ErrorCode.JWT_IS_NOT_VALID);
        } catch (MalformedJwtException e) {
            sendErrorMessage(response, ErrorCode.JWT_IS_MALFORMED);
        } catch (DecodingException e) {
            sendErrorMessage(response, ErrorCode.JWT_DECODING_IS_FAILED);
        } catch (ExpiredJwtException e) {
            sendErrorMessage(response, ErrorCode.JWT_IS_EXPIRED);
        }

    }

    private void sendErrorMessage(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON.toString());
        response.getWriter().write(mapper.writeValueAsString(Api.fail(errorCode)));
    }
}