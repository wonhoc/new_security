package com.new_spring_security.domain.user.controller;

import com.new_spring_security.comm.Api;
import com.new_spring_security.comm.SuccessCode;
import com.new_spring_security.comm.response.Response;
import com.new_spring_security.domain.user.dto.req.JoinUserReqDto;
import com.new_spring_security.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController(value = "/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public Response insertUser(JoinUserReqDto joinUserReqDto) {

        userService.insertUser(joinUserReqDto);

        return Api.success(SuccessCode.COMM_CREATED);
    }
}
