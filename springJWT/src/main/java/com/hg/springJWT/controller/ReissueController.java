package com.hg.springJWT.controller;

import com.hg.springJWT.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReissueController {

    private final JWTUtil jwtUtil;

    public ReissueController(JWTUtil jwtUtil){
        this.jwtUtil=jwtUtil;
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response){

        // refresh token 추출
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            // response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // 토큰 만료 시
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            // response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 사용자 정보 추출
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // 새로운 token 발급
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        //response
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh",newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }

    private Cookie createCookie(String key, String value){
        Cookie cookie=new Cookie(key,value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);

        return cookie;
    }

}