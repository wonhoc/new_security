package com.new_spring_security.comm;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum SuccessCode {
    COMM_OK(                "SUCCESS-COMMON-S001", "요청이 성공적으로 처리되었습니다."),
    COMM_FOUND(             "SUCCESS-COMMON-S002", "성공적으로 조회되었습니다."),
    COMM_CREATED(           "SUCCESS-COMMON-S003", "성공적으로 생성되었습니다."),
    COMM_DELETED(           "SUCCESS-COMMON-S004", "성공적으로 삭제되었습니다."),
    COMM_UPDATED(           "SUCCESS-COMMON-S005", "성공적으로 업데이트되었습니다."),

    USER_CREATED(           "SUCCESS-USER-S001", "사용자 계정이 성공적으로 생성되었습니다."),
    USER_LOGIN_SUCCESS(     "SUCCESS-USER-S002", "사용자가 성공적으로 로그인하였습니다."),

    POSTS_CREATED(          "SUCCESS-POST-S001", "게시글이 성공적으로 생성되었습니다."),
    POSTS_FOUND(            "SUCCESS-POST-S002", "게시글이 성공적으로 조회되었습니다."),
    POSTS_UPDATED(          "SUCCESS-POST-S003", "게시글이 성공적으로 수정되었습니다."),
    POSTS_DELETED(          "SUCCESS-POST-S004", "게시글이 성공적으로 삭제되었습니다."),
    ;

    private final String code;
    private String message;

    public void setMessage(String message) {
        this.message = message;
    }
}