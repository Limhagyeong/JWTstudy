package com.hg.springJWT.jwt;

import com.hg.springJWT.dto.CustomUserDetails;
import com.hg.springJWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

// JWT 검증
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil){
        this.jwtUtil=jwtUtil;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 헤더에서 access에 담긴 토큰을 꺼냄
        String accessToken=request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김 => 권한이 필요 없을수도 있으니까
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰이 있다면 토큰 만료 여부 확인 => 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {
            //response body
            PrintWriter writer=response.getWriter();
            writer.print("토큰이 만료되었습니다");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 category 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {

            //response body
            PrintWriter writer=response.getWriter();
            writer.print("유효하지 않은 토큰입니다");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // username, role 값 추출해서 일시적으로 세션 생성
        String username=jwtUtil.getUsername(accessToken);
        String role=jwtUtil.getRole(accessToken);

        UserEntity userEntity=new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails=new CustomUserDetails(userEntity);

        Authentication authToken=new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities()); // 로그인
        SecurityContextHolder.getContext().setAuthentication(authToken); // 세션 생성

        filterChain.doFilter(request, response);
    }
}
