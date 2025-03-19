package com.new_spring_security.comm.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Response {
    private Boolean result;
    private String code;
    private String message;
}
