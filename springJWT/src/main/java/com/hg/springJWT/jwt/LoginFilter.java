package com.hg.springJWT.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager){
        this.authenticationManager=authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 클라이언트 요청에서 로그인 정보 추출
        String username=obtainUsername(request);
        String password=obtainPassword(request);

        System.out.println(username);

        // 시큐리티에서 로그인정보 검증하기 위해서는 token에 담아야함 (DTO)
        UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(username,password,null);

        // 검증을 위해 token을 AuthenticationManager로 넘김
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행 메소드 (JWT 발급)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        
        System.out.println("success");
    }


    // 로그인 실패 시 실행 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        System.out.println("fail");
    }
}
