package com.hdh.ticketing.security.jwt.util;

import jakarta.servlet.http.Cookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieProvider {
    private static final int ACCESS_TOKEN_EXPIRY = 60*30;
    private static final int REFRESH_TOKEN_EXPIRY = 60*60*24*7;

    public ResponseCookie createAccessTokenCookie(String accessToken){
        return createCookie("accessToken", accessToken, ACCESS_TOKEN_EXPIRY);
    }

    public ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return createCookie("refreshToken", refreshToken, REFRESH_TOKEN_EXPIRY);
    }

    private ResponseCookie createCookie(String name, String value, int maxAge){
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
//                .secure(true) // https만
                .path("/")
                .maxAge(maxAge)
//                .sameSite("None") // 또는 "Lax", "None"
                .build();
        return cookie;
    }

}
