package com.hg.springJWT.repository;

import com.hg.springJWT.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    // 기존 가입 여부 확인
    Boolean existsByUsername(String username);
}
