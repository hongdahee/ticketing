package com.hdh.ticketing.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hdh.ticketing.auth.dto.request.LogoutRequestDto;
import com.hdh.ticketing.security.jwt.domain.RefreshToken;
import com.hdh.ticketing.security.jwt.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class LogoutHandlerImpl implements LogoutHandler {
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            LogoutRequestDto logoutRequestDto = objectMapper.readValue(request.getInputStream(), LogoutRequestDto.class);

            RefreshToken storedToken = refreshTokenRepository.findByValue(logoutRequestDto.getRefreshToken())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하지 않는 리프레쉬 토큰입니다."));

            refreshTokenRepository.delete(storedToken);
        } catch (IOException e) {
            throw new RuntimeException("잘못된 로그아웃 요청 형식입니다.");
        }
    }

//    private String getAccessTokenFromRequest(HttpServletRequest request){
//        String bearerToken = request.getHeader("Authorization");
//
//        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
//            return bearerToken.substring(7);
//        }
//        return null;
//    }
}
