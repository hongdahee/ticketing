package com.hdh.ticketing.security.jwt.util;

import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Component;

@Component
public class CookieProvider {
    private static final int ACCESS_TOKEN_EXPIRY = 60*30;
    private static final int REFRESH_TOKEN_EXPIRY = 60*60*24*7;

    public Cookie createAccessTokenCookie(String accessToken){
        return createCookie("accessToken", accessToken, ACCESS_TOKEN_EXPIRY);
    }

    public Cookie createRefreshTokenCookie(String refreshToken) {
        return createCookie("refreshToken", refreshToken, REFRESH_TOKEN_EXPIRY);
    }

    private Cookie createCookie(String name, String value, int maxAge){
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
//        cookie.setSecure(true); https에서만
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        return cookie;
    }

}
