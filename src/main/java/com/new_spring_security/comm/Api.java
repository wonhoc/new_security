package com.new_spring_security.comm;

import com.new_spring_security.comm.response.DataResponse;
import com.new_spring_security.comm.response.ErrorMapResponse;
import com.new_spring_security.comm.response.Response;

import java.util.Map;

public class Api {

    public static Response success(SuccessCode successCode) {
        return Response.builder()
                .result(true)
                .code(successCode.getCode())
                .message(successCode.getMessage())
                .build();

    }

    public static <T> DataResponse<T> success(SuccessCode successCode, T data) {
        return DataResponse.<T>builder()
                .result(true)
                .code(successCode.getCode())
                .message(successCode.getMessage())
                .data(data)
                .build();
    }

    public static Response fail(ErrorCode errorCode) {
        return Response.builder()
                .result(false)
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();
    }

    public static ErrorMapResponse fail(ErrorCode errorCode, Map<String, String> errorMap) {
        return ErrorMapResponse.builder()
                .result(false)
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .errorMap(errorMap)
                .build();
    }
}
