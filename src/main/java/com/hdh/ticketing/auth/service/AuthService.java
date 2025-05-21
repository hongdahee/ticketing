package com.hdh.ticketing.auth.service;

import com.hdh.ticketing.auth.dto.request.UserAuthRequestDto;
import com.hdh.ticketing.auth.dto.response.UserAuthResponseDto;
import com.hdh.ticketing.security.jwt.TokenProvider;
import com.hdh.ticketing.security.jwt.domain.RefreshToken;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import com.hdh.ticketing.security.jwt.repository.RefreshTokenRepository;
import com.hdh.ticketing.user.domain.SiteUser;
import com.hdh.ticketing.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public UserAuthResponseDto signup(UserAuthRequestDto userAuthRequestDto) {
        if(userRepository.existsByEmail(userAuthRequestDto.getEmail())){
            throw new RuntimeException("이미 가입된 유저입니다");
        }

        SiteUser siteUser = userAuthRequestDto.toSiteUser(passwordEncoder);
        return UserAuthResponseDto.of(userRepository.save(siteUser));
    }


    public TokenDto login(UserAuthRequestDto userAuthRequestDto) {
        SiteUser siteUser = userRepository.findByUsername(userAuthRequestDto.getUsername())
                .orElseThrow(() -> new RuntimeException("id가 일치하는 사용자가 존재하지 않습니다"));

        if(!passwordEncoder.matches(userAuthRequestDto.getPassword(), siteUser.getPassword())){
            throw new BadCredentialsException("잘못된 비밀번호입니다");
        }

        UsernamePasswordAuthenticationToken authenticationToken = userAuthRequestDto.toAuthentication();
        Authentication authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);

        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);

        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        return tokenDto;
    }
}
