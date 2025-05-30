package com.hdh.ticketing.auth.dto.request;

import lombok.Getter;

@Getter
public class LogoutRequestDto {
    private String accessToken;
    private String refreshToken;
}
