package com.hdh.ticketing.auth.oauth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hdh.ticketing.security.jwt.util.CookieProvider;
import com.hdh.ticketing.security.jwt.util.TokenProvider;
import com.hdh.ticketing.security.jwt.domain.RefreshToken;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import com.hdh.ticketing.security.jwt.repository.RefreshTokenRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieProvider cookieProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("Authenticated user: {}", authentication.getName());
        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);

        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        Cookie accessTokenCookie = cookieProvider.createAccessTokenCookie(tokenDto.getAccessToken());
        Cookie refreshTokenCookie = cookieProvider.createRefreshTokenCookie(tokenDto.getRefreshToken());
        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
        response.sendRedirect("http://localhost:5173/token-sync");

//        response.setContentType("application/json");
//        response.setCharacterEncoding("UTF-8");
//        response.setStatus(HttpServletResponse.SC_OK);
//
//        ObjectMapper objectMapper = new ObjectMapper();
//        response.getWriter().write(objectMapper.writeValueAsString(tokenDto));
    }
}
