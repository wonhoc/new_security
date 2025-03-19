package com.new_spring_security.comm;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ErrorCode {

    COMM_INTERNAL_SERVER_ERROR(         "ERROR-COMM-E001",  "서버 내부 오류가 발생했습니다."),
    COMM_UNKNOWN_ERROR(                 "ERROR-COMM-E002",  "서버 내부 오류가 발생했습니다."),

    USER_IS_NOT_FOUND(                  "ERROR-USER-E001", "사용자를 찾을 수 없습니다."),
    USER_IS_NOT_FOUND_BY_EMAIL(         "ERROR-USER-E002", "email을 찾을 수 없습니다."),
    USERS_IS_NOT_FOUND_BY_TOKEN(        "ERROR-USER-E003", "토큰을 찾을 수 없습니다."),
    USER_IS_INVALID_PASSWORD(           "ERROR-USER-E004", "패스워드가 일치하지 않습니다."),
    USER_IS_LOCKED(                     "ERROR-USER-E005", "사용자 계정이 잠겨있습니다."),
    USER_IS_DISABLED(                   "ERROR-USER-E006", "사용자 계정을 사용할 수 없습니다."),
    USER_ACCOUNT_EXPIRYDATE_IS_EXPIRED( "ERROR-USER-E007", "사용자 계정이 만료되었습니다."),
    USER_PASSWORD_IS_EXPIRED(           "ERROR-USER-E008", "계정의 패스워드가 만료되었습니다."),
    USER_IS_LOGINED_DUPLICATE(          "ERROR-USER-E009", "사용자 계정 세션이 중복되었습니다."),

    JWT_IS_NOT_VALID(                   "ERROR-JWT-E001","유효한 토큰 형식이 아닙니다"),
    JWT_IS_MALFORMED(                   "ERROR-JWT-E002","손상된 토큰입니다."),
    JWT_DECODING_IS_FAILED(             "ERROR-JWT-E003","토큰 디코딩에 실패했습니다."),
    JWT_IS_EXPIRED(                     "ERROR-JWT-E004","만료된 토큰입니다. 재로그인 부탁드립니다."),
    ;

    private final String code;
    private String message;

    public void setMessage(String message) {
        this.message = message;
    }
}
