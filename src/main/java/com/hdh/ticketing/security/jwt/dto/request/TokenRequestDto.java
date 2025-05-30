package com.hdh.ticketing.security.jwt.dto.request;

import lombok.Getter;

@Getter
public class TokenRequestDto {
    private String accessToken;
    private String refreshToken;
}
