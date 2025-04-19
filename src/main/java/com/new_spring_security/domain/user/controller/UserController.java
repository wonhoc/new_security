package com.new_spring_security.domain.user.controller;

import com.new_spring_security.comm.Api;
import com.new_spring_security.comm.SuccessCode;
import com.new_spring_security.comm.response.Response;
import com.new_spring_security.domain.user.dto.req.JoinUserReqDto;
import com.new_spring_security.domain.user.dto.req.LoginReqDto;
import com.new_spring_security.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public Response insertUser(@RequestBody JoinUserReqDto joinUserReqDto) {

        userService.insertUser(joinUserReqDto);

        return Api.success(SuccessCode.COMM_CREATED);
    }

    @PostMapping("/login")
    public void login(@RequestBody LoginReqDto loginDto) {
        // 이 메서드는 실제로 호출되지 않습니다.
        // Spring Security 필터가 이 요청을 가로채서 처리합니다.
        throw new IllegalStateException("이 메서드는 Spring Security에 의해 가로채집니다");
    }
}
