package com.new_spring_security.domain.user.etc;

import com.new_spring_security.comm.ErrorCode;
import com.new_spring_security.handler.exception.CustomApiException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserRoles {

    ROLE_ADMIN(     "ROLE_ADMIN",   "관리자"),
    ROLE_MANAGER(   "ROLE_MANAGER", "운영자"),
    ROLE_MEMBER(    "ROLE_MEMBER",  "회원"),
    ;

    private final String key;
    private final String title;

    public static UserRoles getRole(String key) {

        for (UserRoles usersRole : UserRoles.values()) {
            if (usersRole.getKey().equals(key)) {
                return usersRole;
            }
        }

        throw new CustomApiException(ErrorCode.COMM_INTERNAL_SERVER_ERROR);
    }
}
