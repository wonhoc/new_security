package com.new_spring_security.domain.user.dto.req;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class JoinUserReqDto {

    @Schema(description = "이메일", example = "test@naver.com")
    @NotBlank(message = "이메일을 입력해주세요.")
    @Email(message = "올바른 이메일 형식을 입력해주세요")
    private String email;

    @Schema(description = "비밀번호")
    @NotBlank(message = "비밀번호를 입력해주세요.")
    @Size(min = 4, max = 30, message = "비밀번호는 4자 이상 30자 이하로 입력해주세요.")
    private String password;

    @Schema(description = "이름", example = "홍길동")
    @NotBlank(message = "성함을 입력해주세요.")
    @Size(min = 1, max = 20, message = "이름은 1자 이상 20자 이하로 입력해주세요.")
    private String name;

}
