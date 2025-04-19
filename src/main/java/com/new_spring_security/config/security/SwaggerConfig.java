package com.new_spring_security.config.security;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {

        return new OpenAPI()
                .info(new Info()
                        .title(" API 명세서")
                        .version("1.0")
                        .description("이 API는  위한 도구입니다."))
                .addSecurityItem(
                        new SecurityRequirement().addList("accessTokenAuth")
                )
                .components(
                        new Components().addSecuritySchemes("accessTokenAuth",
                                new SecurityScheme()
                                        .name("accessToken")                     // 헤더 이름
                                        .type(SecurityScheme.Type.APIKEY)        // API Key 방식을 사용
                                        .in(SecurityScheme.In.HEADER)            // HEADER에서 사용
                        )
                );
    }
}
