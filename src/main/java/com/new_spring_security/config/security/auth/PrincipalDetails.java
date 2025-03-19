package com.new_spring_security.config.security.auth;

import com.new_spring_security.domain.user.dto.res.LoginResDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @class   PrincipalDetails
 * @brief   권합 삽입
 * @details 사용자에 해당하는 권한을 넣어준다
 *          시큐리티가 가지고 있는 시큐리티_session에 들어갈 수 있는 Object는 정해져 있음(Object == Authentication객체)
 * @author  최원호
 * @date    2023.05.02
 * version  1.0
 */

@Getter
@AllArgsConstructor
public class PrincipalDetails implements UserDetails {

    private LoginResDto loginResponseDto;


    /**
     * @details 사용자 정보에 권한을 삽입한다.
     * @return  권한
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        authorities.add(new SimpleGrantedAuthority(loginResponseDto.getRole().getKey()));

        return authorities;
    }

    /**
     * @brief 패스워드 호출.
     * @return  패스워드
     */
    @Override
    public String getPassword() {
        return loginResponseDto.getPassword();
    }

    /**
     * @brief 유저네임 호출.
     * @return  이메일
     */
    @Override
    public String getUsername() {
        return loginResponseDto.getEmail();
    }


    /**
     * @brief 계정의 만료 여부 리턴 -> true 를 리턴하면 만료되지 않음을 의미
     * @return  true
     */
    @Override
    public boolean isAccountNonExpired() {

        LocalDateTime currentDateTime = LocalDateTime.now();
        LocalDateTime accountExpiryDate = loginResponseDto.getAccountExpiryDate();

        loginResponseDto.getAccountExpiryDate();

        return currentDateTime.isBefore(accountExpiryDate);
    }


    /**
     * @brief 계정의 잠금 여부 리턴 -> true 를 리턴하면 사용가능한 계정을 의미
     * @return  true
     */
    @Override
    public boolean isAccountNonLocked() {
        return loginResponseDto.isNonLock();
    }

    /**
     * @brief 비밀번호 만료 여부 리턴 -> true 를 리턴하면 사용가능한 계정을 의미
     * @return  true
     */
    @Override
    public boolean isCredentialsNonExpired() {

        LocalDateTime currentDateTime = LocalDateTime.now();
        LocalDateTime credentialsExpiryDate = loginResponseDto.getCredentialsExpiryDate();

        return currentDateTime.isBefore(credentialsExpiryDate);
    }

    /**
     * @brief 계정의 활성화 여부 리턴 -> true 를 리턴하면 사용가능한 계정을 의미
     * @return  true
     */
    @Override
    public boolean isEnabled() {

        return loginResponseDto.isEnabled();
    }
}
