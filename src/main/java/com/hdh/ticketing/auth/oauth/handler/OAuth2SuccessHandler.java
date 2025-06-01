package com.hdh.ticketing.auth.oauth.handler;

import com.hdh.ticketing.auth.service.AuthService;
import com.hdh.ticketing.security.jwt.CookieProvider;
import com.hdh.ticketing.security.jwt.TokenProvider;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private final AuthService authService;
    private final CookieProvider cookieProvider;
//    private static final String URI = "/auth/success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        TokenDto tokenDto = authService.socialLogin(authentication);
        Cookie accessTokenCookie = cookieProvider.generateAccessTokenCookie(tokenDto.getAccessToken());
        response.addCookie(accessTokenCookie);
    }
}
