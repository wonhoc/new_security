package com.new_spring_security.comm.response;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class ErrorMapResponse {
    private Boolean result;
    private String code;
    private String message;
    private Map<String, String> errorMap;
}
