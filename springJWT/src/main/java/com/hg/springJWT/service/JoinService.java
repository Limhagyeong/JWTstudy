package com.hg.springJWT.service;

import com.hg.springJWT.repository.UserRepository;
import dto.JoinDTO;
import entity.UserEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository,BCryptPasswordEncoder bCryptPasswordEncoder){
        this.userRepository=userRepository;
        this.bCryptPasswordEncoder=bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO){

        String username=joinDTO.getUsername();
        String password=joinDTO.getPassword();

        // 기존 회원 여부 확인
        Boolean isExist=userRepository.existsByUsername(username);
        if(isExist){
            return;
        }

        // 회원 가입
        UserEntity data=new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password)); // 비빌번호 암호화
        data.setRole("ROLE_ADMIN");

        userRepository.save(data); // DB 저장

    }

}
