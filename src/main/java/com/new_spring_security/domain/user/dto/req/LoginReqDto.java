package com.new_spring_security.domain.user.dto.req;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class LoginReqDto {

    @NotBlank(message = "이메일을 입력해주세요.")
    @Email(message = "올바른 이메일 형식을 입력해주세요")
    private String email;

    @NotBlank(message = "비밀번호를 입력해주세요.")
    @Size(min = 4, max = 30, message = "비밀번호는 4자 이상 30자 이하로 입력해주세요.")
    private String password;
}
