package com.hg.springJWT.jwt;

import com.hg.springJWT.dto.CustomUserDetails;
import com.hg.springJWT.entity.RefreshEntity;
import com.hg.springJWT.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository){
        this.authenticationManager=authenticationManager;
        this.jwtUtil=jwtUtil;
        this.refreshRepository=refreshRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 클라이언트 요청에서 로그인 정보 추출
        String username=obtainUsername(request);
        String password=obtainPassword(request);

        // 시큐리티에서 로그인정보 검증하기 위해서는 token에 담아야함 (DTO)
        UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(username,password,null);

        // 검증을 위해 token을 AuthenticationManager로 넘김
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행 메소드 (JWT 발급)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // username
        String username=authentication.getName();

        // role
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // 토큰 생성 메소드
        String access=jwtUtil.createJwt("access",username,role,600000L);
        String refresh=jwtUtil.createJwt("refresh",username,role,86400000L);

        // 최초 발급 된 refresh 토큰 저장 (로그아웃 시 삭제)
        addRefreshEntity(username, refresh, 86400000L);

        // 응답 생성
        response.addHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    // 쿠키 생성
    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);

        return cookie;
    }

    // refresh 토근 DB 저장
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date=new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity=new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    // 로그인 실패 시 실행 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        response.setStatus(401);
    }
}
