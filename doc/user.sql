-- template.users definition

CREATE TABLE `users` (
                         `userId` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '시퀀스',
                         `email` varchar(255) NOT NULL COMMENT '이메일',
                         `name` varchar(255) NOT NULL COMMENT '이름',
                         `password` varchar(255) NOT NULL COMMENT '비밀번호',
                         `register_user` varchar(255) DEFAULT NULL COMMENT '생성자',
                         `update_user` varchar(255) DEFAULT NULL COMMENT '수정자',
                         `username` varchar(255) NOT NULL COMMENT '아이디',
                         `role` enum('ADMIN','MANAGER') NOT NULL COMMENT '권한',
                         `is_enabled` bit(1) NOT NULL COMMENT '사용 가능 상태 [1=TRUE,\r\n       0=FALSE]',
                         `is_non_active` bit(1) NOT NULL COMMENT '계정 사용가능 상태 [1=TRUE,\r\n       0=FALSE]',
                         `is_non_lock` bit(1) NOT NULL COMMENT '계정 잠금 상태 [1=TRUE,\r\n       0=FALSE]',
                         `login_fail_count` int(11) NOT NULL COMMENT '로그인 실패횟수',
                         `accountExpiryDate` datetime(6) NOT NULL COMMENT '계정 만료일',
                         `credentialsExpiryDate` datetime(6) NOT NULL COMMENT '비밀번호 만료일 (application.yml 참조)',
                         `lastUpdatePwDtm` datetime(6) NOT NULL COMMENT '마지막 비밀번호 업데이트 일시',
                         `last_login_dtm` datetime(6) NOT NULL COMMENT '마지막 로그인 일시',
                         `register_dtm` datetime(6) DEFAULT NULL COMMENT '생성일',
                         `update_dtm` datetime(6) DEFAULT NULL COMMENT '수정일',
                         PRIMARY KEY (`userId`),
                         UNIQUE KEY `UK6dotkott2kjsp8vw4d0m25fb7` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;