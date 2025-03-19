package com.new_spring_security.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.new_spring_security.comm.Api;
import com.new_spring_security.comm.ErrorCode;
import com.new_spring_security.comm.SuccessCode;
import com.new_spring_security.config.security.auth.PrincipalDetails;
import com.new_spring_security.config.security.jwt.JwtTokenProvider;
import com.new_spring_security.domain.user.dto.req.LoginReqDto;
import com.new_spring_security.domain.user.dto.res.LoginResDto;
import com.new_spring_security.domain.user.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.io.IOException;

/**
 * @package com.example.spring_security.config.security.jwt.filter
 * @class   JwtAuthenticationFilter
 * @brief   인증 필터
 * @author  최원호
 * @date    2023.06.22
 * version  1.0
 */
@Slf4j
@RequiredArgsConstructor
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    /**
     * @brief   인증 요청시에 실행되는 함수 (/login 요청 시 실행됨)
     * @param   req
     * @param   res
     * @return  Authentication               회원가입 결과
     */
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {

        ObjectMapper om = new ObjectMapper();
        Authentication authentication = null;

        try {

            /* 1. username(email)과 password를 받는다 */
            LoginReqDto loginDto = om.readValue(req.getInputStream(), LoginReqDto.class);


            /* 2. email과 password를 이용하여 token 발급 */
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());


            /* 3. 정상적인 로그인 여부 확인 */
            /* authenticate(토큰) 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
               loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
               UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
               UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
               Authentication 객체를 만들어서 필터체인으로 리턴해준다. */
            authentication = authenticationManager.authenticate(authenticationToken);

        } catch (IOException e) {
            e.printStackTrace();
        }

        /* 4. authentication 반환 */
        return authentication;
    }

    /**
     * @brief   로그인 성공 시 발생하는 이벤트
     * @return  Authentication
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {


        ObjectMapper om = new ObjectMapper();
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        Long userId = principalDetails.getLoginResponseDto().getUserId();

        // 비밀번호 실패 횟수 0으로 초기화
        userService.resetUserPasswordFailCount(userId);

        // 만료 일시 초기화
        userService.setUserAccountExpiryDate(userId);

        String accessToken = jwtTokenProvider.createAccessToken(principalDetails.getUsername(), principalDetails.getLoginResponseDto().getRole());
        String refreshToken = jwtTokenProvider.createRefreshToken(principalDetails.getUsername());

        // refreshToken 세팅
        userService.setUserRefreshToken(userId, refreshToken);

        // 헤더에 세팅
        jwtTokenProvider.setAccessTokenToHeader(response, accessToken);
        jwtTokenProvider.setRefreshTokenToHeader(response, refreshToken);

        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setContentType(MediaType.APPLICATION_JSON.toString());

        response.getWriter().write(om.writeValueAsString(Api.success(SuccessCode.USER_LOGIN_SUCCESS)));
    }

    /**
     * @brief   로그인 실패 시 발생하는 이벤트
     * @return  Authentication
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException exception) throws IOException, ServletException {
        ErrorCode errorCode = null;
        String email = (String) request.getAttribute("email");

        ObjectMapper om = new ObjectMapper();

        // 유저 email로 못 찾았을 경우
        if (exception instanceof InternalAuthenticationServiceException || exception instanceof UsernameNotFoundException) {
            errorCode = ErrorCode.USERS_IS_NOT_FOUND_BY_TOKEN;

        } else if(exception instanceof BadCredentialsException) {   // 유저 패스워드를 잘못 입력했을 경우
            errorCode = ErrorCode.USER_IS_INVALID_PASSWORD;

            LoginResDto user = userService.getUserByEmail(email);

            long userId = user.getUserId();

            userService.setUserLoginFailCount(userId);

        } else if(exception instanceof LockedException) {               // 유저의 isNonLock이 false인 경우
            errorCode = ErrorCode.USER_IS_LOCKED;

        } else if(exception instanceof DisabledException) {             // 유저의 isEnabled가 false인 경우
            errorCode = ErrorCode.USER_IS_DISABLED;

        } else if(exception instanceof AccountExpiredException) {       // 유저의 accountExpiryDate가 지난 경우
            errorCode = ErrorCode.USER_ACCOUNT_EXPIRYDATE_IS_EXPIRED;

        } else if(exception instanceof CredentialsExpiredException) {   // 유저의 credentialsNonExpired이 만료된 경우
            errorCode = ErrorCode.USER_PASSWORD_IS_EXPIRED;

        } else if(exception instanceof SessionAuthenticationException){ // 세션이 중복된 경우
            errorCode = ErrorCode.USER_IS_LOGINED_DUPLICATE;
        } else {
            errorCode = ErrorCode.COMM_UNKNOWN_ERROR;

        }

        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON.toString());
        response.getWriter().write(om.writeValueAsString(Api.fail(errorCode)));
    }
}
