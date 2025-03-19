package com.new_spring_security.config.security;

import com.new_spring_security.config.security.auth.PrincipalDetailsService;
import com.new_spring_security.config.security.filter.AuthenticationFilter;
import com.new_spring_security.config.security.jwt.JwtOncePerRequestFilter;
import com.new_spring_security.config.security.jwt.JwtTokenProvider;
import com.new_spring_security.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final PrincipalDetailsService principalDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;
    private final Environment env;

    @Value("${app.loginUrl}") private String LOGIN_URL;

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {

        // 로그인(인증)을 Spring Security가 처리하도록 설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(principalDetailsService).passwordEncoder(bCryptPasswordEncoder);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
        http.authenticationManager(authenticationManager);

        // http.cors((cors) -> cors.disable()); // 주석처리해야 리액트 에서 요청가능
        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.headers((headers) -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // JWT 인증 필터 추가
        http.addFilterBefore(new JwtOncePerRequestFilter(jwtTokenProvider, userService, env), UsernamePasswordAuthenticationFilter.class);

        // 로그인 인증 필터 추가
        http.addFilterBefore(getAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);


        // 인가 처리
        http.authorizeHttpRequests((auth) -> auth
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() // 정적 리소스에 대한 보안 무시
                        .requestMatchers(PERMIT_SWAGGER_URL_ARRAY).permitAll()  // Swagger UI에 대한 보안 무시

                        .requestMatchers(new AntPathRequestMatcher("/api/login", "POST")).permitAll()   // 로그인은 누구나 접근 가능
                        .requestMatchers(new AntPathRequestMatcher("/api/users", "POST")).permitAll()   // 회원가입은 누구나 접근 가능

                        .requestMatchers(new AntPathRequestMatcher("/api/posts/**")).hasAnyRole("ADMIN", "MANAGER", "USER") // 게시글 작성은 인증된 사용자만 가능

                        //.anyRequest().permitAll() // 모든 요청 허용
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증된 사용자만 접근 가능
                //.anyRequest().hasRole("ADMIN") // 그 외 모든 요청은 ADMIN 권한이 있어야 접근 가능
                //.anyRequest().denyAll() // 그 외 모든 요청은 거부
        );


        return http.build();
    }

    public AuthenticationFilter getAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
        AuthenticationFilter authenticationFilter =
                new AuthenticationFilter(jwtTokenProvider, authenticationManager, userService);
        authenticationFilter.setFilterProcessesUrl(LOGIN_URL);
        return authenticationFilter;
    }

    private static final String[] PERMIT_SWAGGER_URL_ARRAY = {
            "/pagination.html",
            "/v3/api-docs",
            "/v3/api-docs/swagger-config",
            "/swagger-resources/**",
            "/swagger-ui/**",
            "/webjars/**", "/swagger/**"
    };
}
