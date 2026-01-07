package com.hdh.ticketing.user.dto;

import com.hdh.ticketing.user.domain.SiteUser;
import lombok.Getter;

@Getter
public class UserInfoDto {
    private Long id;
    private String username;
    private String nickname;

    public UserInfoDto(SiteUser user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.nickname = user.getNickname();
    }
}
