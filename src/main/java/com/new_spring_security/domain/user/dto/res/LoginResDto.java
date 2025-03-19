package com.new_spring_security.domain.user.dto.res;

import com.new_spring_security.domain.user.entity.User;
import com.new_spring_security.domain.user.etc.UserRoles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResDto {

    private long userId;
    private String email;
    private String password;
    private UserRoles role;
    private LocalDateTime accountExpiryDate;
    private LocalDateTime credentialsExpiryDate;
    private boolean isNonLock;
    private boolean isEnabled;
    private int loginFailCount;

    public LoginResDto(User user) {
        this.userId = user.getUserId();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.role = user.getRole();
        this.accountExpiryDate = user.getAccountExpiryDate();
        this.credentialsExpiryDate = user.getCredentialsExpiryDate();
        this.isNonLock = user.isNonLock();
        this.isEnabled = user.isEnabled();
        this.loginFailCount = user.getLoginFailCount();
    }
}
