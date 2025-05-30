package com.hdh.ticketing.auth.dto.request;

import com.hdh.ticketing.user.domain.Role;
import com.hdh.ticketing.user.domain.SiteUser;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
public class UserAuthRequestDto {

    private String username;
    private String password;
    private String email;
    private String nickname;
    private String name;
    private Role role;
    private String profileImg;

    public SiteUser toSiteUser(PasswordEncoder passwordEncoder){
        SiteUser.SiteUserBuilder builder = SiteUser.builder()
                .username(this.username)
                .password(this.password)
                .password(passwordEncoder.encode(this.password))
                .email(this.email)
                .nickname(this.nickname)
                .name(this.name)
                .role(Role.USER);

        if (this.profileImg != null && !this.profileImg.isEmpty()) {
            builder.profileImg(this.profileImg);
        }

        return builder.build();
    }

    public UsernamePasswordAuthenticationToken toAuthentication(){
        return new UsernamePasswordAuthenticationToken(username, password);
    }
}