package com.hdh.ticketing.auth.oauth.service;

import com.hdh.ticketing.auth.oauth.dto.OAuth2UserInfo;
import com.hdh.ticketing.security.PrincipalDetails;
import com.hdh.ticketing.user.domain.SiteUser;
import com.hdh.ticketing.user.repository.UserRepository;
import jakarta.security.auth.message.AuthException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        Map<String, Object> userAttributes = oAuth2User.getAttributes();

        try {
            OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfo.of(registrationId, userAttributes);
            SiteUser user = getOrSave(oAuth2UserInfo);
            return new PrincipalDetails(user, userAttributes, userNameAttributeName);
        } catch (AuthException e) {
            throw new RuntimeException(e);
        }
    }

    private SiteUser getOrSave(OAuth2UserInfo oAuth2UserInfo){
        SiteUser user = userRepository.findByEmail(oAuth2UserInfo.email())
                .orElseGet(oAuth2UserInfo::toEntity);
        return userRepository.save(user);
    }
}
