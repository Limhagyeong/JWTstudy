package com.hg.springJWT.jwt;

import com.hg.springJWT.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil){
        this.authenticationManager=authenticationManager;
        this.jwtUtil=jwtUtil;
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
        CustomUserDetails customUserDetails= (CustomUserDetails) authentication.getPrincipal();
        String username= customUserDetails.getUsername();

        // role
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // 토큰 생성 메소드
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // 헤더에 담아 응답
        response.addHeader("Authorization", "Bearer " + token);
    }


    // 로그인 실패 시 실행 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        response.setStatus(401);
    }
}
