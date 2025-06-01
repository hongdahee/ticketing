package com.hdh.ticketing.security.jwt;

import jakarta.servlet.http.Cookie;

public class CookieProvider {
    public Cookie generateAccessTokenCookie(String accessToken){
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true); // https에서만 전달
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(60*30); // 30분

        return accessTokenCookie;
    }
}
