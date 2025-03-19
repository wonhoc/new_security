package com.new_spring_security.domain.comm.etity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.hibernate.annotations.Comment;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public class BaseEntity extends BaseTimeEntity {

    @CreatedBy
    @Column(updatable = false)
    @Comment("생성자")
    private String registerUser;

    @LastModifiedBy
    @Comment("수정자")
    private String updateUser;
}
