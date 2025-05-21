package com.hdh.ticketing.auth.dto.response;

import com.hdh.ticketing.user.domain.Role;
import com.hdh.ticketing.user.domain.SiteUser;
import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AccessLevel;
import lombok.Getter;

@Getter
public class UserAuthResponseDto {

    private Long id;
    private String username;

    @Getter(AccessLevel.NONE)
    private String password;

    private String email;
    private String nickname;
    private String name;
    private Role role;
    private String profileImg;

    private UserAuthResponseDto(Long id, String username, String email,
                                String nickname, String name, Role role, String profileImg){
        this.id = id;
        this.username = username;
        this.email = email;
        this.nickname = nickname;
        this.name = name;
        this.role = role;
        this.profileImg = profileImg;
    }

    public static UserAuthResponseDto of(SiteUser siteUser){
        return new UserAuthResponseDto(
                siteUser.getId(),
                siteUser.getUsername(),
                siteUser.getEmail(),
                siteUser.getNickname(),
                siteUser.getName(),
                siteUser.getRole(),
                siteUser.getProfileImg()
        );
    }
}
