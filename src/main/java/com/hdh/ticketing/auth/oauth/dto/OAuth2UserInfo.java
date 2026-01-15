package com.hdh.ticketing.auth.oauth.dto;

import com.hdh.ticketing.user.domain.Provider;
import com.hdh.ticketing.user.domain.Role;
import com.hdh.ticketing.user.domain.SiteUser;
import jakarta.security.auth.message.AuthException;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Builder
public record OAuth2UserInfo(
        Provider provider, // google, kakao
        String providerId, // 구글 sub, 카카오 id(유저 식별 id)
        String username,
        String name,
        String email,
        String profile
) {

    public static OAuth2UserInfo of(String registrationId, Map<String, Object> attributes) throws AuthException {
        return switch(registrationId){
            case "google" -> ofGoogle(attributes);
            case "kakao" -> ofKakao(attributes);
            default ->  throw new AuthException("지원하지 않는 소셜 로그인 공급자입니다.");
        };
    }

    private static OAuth2UserInfo ofGoogle(Map<String, Object> attributes){
        return OAuth2UserInfo.builder()
                .provider(Provider.GOOGLE)
                .providerId((String) attributes.get("sub"))
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .username((String) attributes.get("email"))
                .profile((String) attributes.get("picture"))
                .build();
    }

    private static OAuth2UserInfo ofKakao(Map<String, Object> attributes){
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = account == null ? null : (Map<String, Object>) account.get("profile");

        String nickname = profile == null ? null : (String) profile.get("nickname");
        String profileImg = profile == null ? null : (String) profile.get("profile_image_url");
        String email = account == null ? null : (String) account.get("email");

        Object idObj = attributes.get("id");
        String providerId = String.valueOf(idObj);

        return OAuth2UserInfo.builder()
                .provider(Provider.KAKAO)
                .providerId(providerId)
                .name(nickname)
                .email(email)
                .username(email)
                .profile(profileImg)
                .build();
    }

    public SiteUser toEntity(){
        return SiteUser.builder()
                .name(name)
                .nickname(name)
                .username(username)
                .provider(provider)
                .email(email)
                .profileImg(profile)
                .role(Role.USER)
                .build();
    }
}
