package com.hg.springJWT.repository;

import com.hg.springJWT.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {
    // refresh 토큰 검증
    Boolean existsByRefresh(String refresh);
    // refresh 재발급 시 기존 토큰 삭제
    @Transactional
    void deleteByRefresh(String refresh);
}
