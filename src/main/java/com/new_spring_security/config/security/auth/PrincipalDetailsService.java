package com.new_spring_security.config.security.auth;

import com.new_spring_security.comm.ErrorCode;
import com.new_spring_security.domain.user.dto.res.LoginResDto;
import com.new_spring_security.domain.user.entity.User;
import com.new_spring_security.domain.user.repository.UserRepository;
import com.new_spring_security.handler.exception.CustomApiException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND_BY_EMAIL));

        return new PrincipalDetails(new LoginResDto(user));
    }
}
