package com.hg.springJWT.repository;

import com.hg.springJWT.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    // 가입 여부 확인
    Boolean existsByUsername(String username);

    // DB에서 회원 조회 => 로그인 인증을 위함
    UserEntity findByUsername(String username);
}
