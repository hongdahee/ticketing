package com.hdh.ticketing.auth.oauth.handler;

import com.hdh.ticketing.security.PrincipalDetails;
import com.hdh.ticketing.security.jwt.util.CookieProvider;
import com.hdh.ticketing.security.jwt.util.TokenProvider;
import com.hdh.ticketing.security.jwt.domain.RefreshToken;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import com.hdh.ticketing.security.jwt.repository.RefreshTokenRepository;
import com.hdh.ticketing.user.domain.SiteUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
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

        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        SiteUser user = principal.user(); // PrincipalDetails에 있는 SiteUser 불러오기

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        ResponseCookie accessTokenCookie = cookieProvider.createAccessTokenCookie(tokenDto.getAccessToken());
        ResponseCookie refreshTokenCookie = cookieProvider.createRefreshTokenCookie(tokenDto.getRefreshToken());
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        response.sendRedirect("http://localhost:5173/auth/callback");
    }
}
