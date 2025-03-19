package com.new_spring_security.domain.user.entity;

import com.new_spring_security.domain.comm.etity.BaseEntity;
import com.new_spring_security.domain.user.etc.UserRoles;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.DynamicInsert;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Builder
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@DynamicInsert
@ToString(exclude = "")
@EntityListeners(AuditingEntityListener.class)
@Entity
@Table(name = "users")
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Comment("시퀀스")
    private Long userId;

    @Column(nullable = false)
    @Comment("비밀번호")
    private String password;

    @Column(unique = true, nullable = false)
    @Comment("이메일")
    private String email;

    @Column(nullable = false)
    @Comment("이름")
    private String name;

    @Column(nullable = true)
    @Comment("refresh token")
    private String refreshToken;


    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Comment("권한")
    private UserRoles role;


    @Column(nullable = false)
    @Comment("계정 잠금 상태 [1=TRUE,0=FALSE]")
    private boolean isNonLock;

    @Column(nullable = false)
    @Comment("사용 가능 상태 [1=TRUE,0=FALSE]")
    private boolean isEnabled;

    @Column(nullable = false)
    @Comment("로그인 실패횟수")
    private Integer loginFailCount;

    @Column(nullable = true)
    @Comment("마지막 로그인 일시")
    private LocalDateTime lastLoginDtm;

    @Column(nullable = false)
    @Comment("계정 만료일")
    private LocalDateTime accountExpiryDate; // application.yml 참조

    @Column(nullable = true)
    @Comment("마지막 비밀번호 업데이트 일시")
    private LocalDateTime lastUpdatePwDtm;

    @Column(nullable = false)
    @Comment("비밀번호 만료일 (application.yml 참조)")
    private LocalDateTime credentialsExpiryDate; // application.yml 참조
}
