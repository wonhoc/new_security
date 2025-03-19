package com.new_spring_security.handler.exception;

import com.new_spring_security.comm.ErrorCode;
import lombok.Getter;

@Getter
public class CustomApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public CustomApiException(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }
}
