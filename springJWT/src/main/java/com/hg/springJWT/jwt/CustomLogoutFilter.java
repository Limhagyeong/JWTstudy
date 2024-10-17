package com.hg.springJWT.jwt;

import com.hg.springJWT.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    public CustomLogoutFilter(JWTUtil jwtUtil, RefreshRepository refreshRepository){
        this.jwtUtil=jwtUtil;
        this.refreshRepository=refreshRepository;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        // ServletResponse => 서블릿 API 최상위 인터페이스
        // HttpServletRequest => HTTP 상태 코드, 헤더, 쿠키 등 HTTP 관련 응답 처리를 할 수 있는 메서드 제공
        doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        //path and method verify
        String requestUri=request.getRequestURI();
        if (!requestUri.matches("^\\/logout$")) {
            filterChain.doFilter(request, response); // 로그아웃 경로가 아니면 다음 필터로 넘김
            return;
        }
        String requestMethod=request.getMethod();
        if (!requestMethod.equals("POST")) { // POST 요청에 대해서만 로그아웃 진행
            filterChain.doFilter(request, response);
            return;
        }

        //refresh token 추출
        String refresh=null;
        Cookie[] cookies=request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        //refresh 토큰 존재 여부 확인
        if (refresh == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //만료 확인
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category=jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist=refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        refreshRepository.deleteByRefresh(refresh);

        //Refresh 토큰 Cookie 값 0
        Cookie cookie=new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }


}
