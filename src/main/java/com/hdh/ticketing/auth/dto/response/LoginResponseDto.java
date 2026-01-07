package com.hdh.ticketing.auth.dto.response;

import com.hdh.ticketing.auth.dto.request.UserAuthRequestDto;
import com.hdh.ticketing.user.domain.SiteUser;
import com.hdh.ticketing.user.dto.UserInfoDto;
import lombok.Getter;

@Getter
public class LoginResponseDto {
    private UserInfoDto user;
    private String loginType;

    public LoginResponseDto(UserInfoDto user, String loginType) {
        this.user = user;
        this.loginType = loginType;
    }

}
