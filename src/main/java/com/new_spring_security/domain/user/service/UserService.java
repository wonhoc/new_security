package com.new_spring_security.domain.user.service;

import com.new_spring_security.comm.ErrorCode;
import com.new_spring_security.domain.user.dto.req.JoinUserReqDto;
import com.new_spring_security.domain.user.dto.res.LoginResDto;
import com.new_spring_security.domain.user.entity.User;
import com.new_spring_security.domain.user.etc.UserRoles;
import com.new_spring_security.domain.user.repository.UserRepository;
import com.new_spring_security.handler.exception.CustomApiException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${app.member.loginfailcount}") private int LOGIN_FAIL_COUNT;
    @Value("${app.member.loginExpiryDay}") private int LOGIN_EXPIRY_DAY;

    @Transactional
    public void insertUser(JoinUserReqDto joinUserReqDto) {

        LocalDateTime currentDateTime = LocalDateTime.now();
        LocalDateTime newDateTime = currentDateTime.plusDays(LOGIN_EXPIRY_DAY);

        User joinUser = User.builder()
                .email(joinUserReqDto.getEmail())
                .password(bCryptPasswordEncoder.encode(joinUserReqDto.getPassword()))
                .name(joinUserReqDto.getName())
                .role(UserRoles.ROLE_MEMBER)
                .isNonLock(true)
                .isEnabled(true)
                .loginFailCount(0)
                .lastLoginDtm(newDateTime)
                .lastUpdatePwDtm(currentDateTime)
                .credentialsExpiryDate(newDateTime)
                .accountExpiryDate(newDateTime)
                .build();

        userRepository.save(joinUser);
    }

    @Transactional
    public void resetUserPasswordFailCount(Long userId) {

        User user = userRepository.findById(userId).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND));

        user.setLoginFailCount(0);
    }

    @Transactional(readOnly = true)
    public LoginResDto getUserByEmail(String email) {

        User user = userRepository.findByEmail(email).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND));

        return new LoginResDto(user);
    }

    @Transactional(readOnly = true)
    public LoginResDto getUserByRefreshToken(String refreshToken) {

        User user = userRepository.findByRefreshToken(refreshToken).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND));

        return new LoginResDto(user);
    }

    @Transactional
    public String setUserLoginFailCount(Long userId) {

        User user = userRepository.findById(userId).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND));

        user.setLoginFailCount(user.getLoginFailCount() + 1);

        String message = "";

        if (user.getLoginFailCount() >= LOGIN_FAIL_COUNT) {
            user.setNonLock(false);
            message = LOGIN_FAIL_COUNT + "회 이상 비밀번호를 잘못입력하셔서 계정 잠금처리가 되었습니다.";
        } else {
            message = "비밀번호가 틀립니다. " + user.getLoginFailCount() + "회 잘못입력하셨습니다.";
        }

        return message;
    }

    @Transactional
    public void setUserAccountExpiryDate(Long userId) {

        User user = userRepository.findById(userId).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND));

        LocalDateTime currentDateTime = LocalDateTime.now();
        LocalDateTime newDateTime = currentDateTime.plusDays(LOGIN_EXPIRY_DAY);

        user.setLastLoginDtm(currentDateTime);
        user.setAccountExpiryDate(newDateTime);
    }

    @Transactional
    public void setUserRefreshToken(Long userId, String refreshToken) {

        User user = userRepository.findById(userId).orElseThrow(() -> new CustomApiException(ErrorCode.USER_IS_NOT_FOUND));

        user.setRefreshToken(refreshToken);
    }
}
