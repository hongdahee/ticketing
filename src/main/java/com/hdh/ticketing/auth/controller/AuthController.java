package com.hdh.ticketing.auth.controller;

import com.hdh.ticketing.auth.dto.request.UserAuthRequestDto;
import com.hdh.ticketing.auth.dto.response.LoginResponseDto;
import com.hdh.ticketing.auth.dto.response.UserAuthResponseDto;
import com.hdh.ticketing.auth.service.AuthService;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import com.hdh.ticketing.security.jwt.dto.request.TokenRequestDto;
import com.hdh.ticketing.security.jwt.util.CookieProvider;
import com.hdh.ticketing.user.domain.SiteUser;
import com.hdh.ticketing.user.dto.UserInfoDto;
import com.hdh.ticketing.user.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final UserService userService;
    private final CookieProvider cookieProvider;

    @PostMapping("/signup")
    public ResponseEntity<UserAuthResponseDto> signup(@RequestBody UserAuthRequestDto userAuthRequestDto){
        return ResponseEntity.ok(authService.signup(userAuthRequestDto));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody UserAuthRequestDto userAuthRequestDto,
                                          HttpServletResponse response){
        // 액세스 토큰 저장
        TokenDto tokenDto = authService.login(userAuthRequestDto);
        response.setHeader("Authorization", "Bearer " + tokenDto.getAccessToken());

        // 리프레시 토큰 저장
        ResponseCookie refreshTokenCookie = cookieProvider.createRefreshTokenCookie(tokenDto.getRefreshToken());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        SiteUser user = userService.findUserByUsername(userAuthRequestDto.getUsername());
        UserInfoDto userInfo = new UserInfoDto(user);

        LoginResponseDto loginResponse = new LoginResponseDto(userInfo, "local");

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenDto> reissue(@RequestBody TokenRequestDto tokenRequestDto){
        return ResponseEntity.ok(authService.reissue(tokenRequestDto));
    }

    @GetMapping("/cookie/convert")
    public ResponseEntity<?> convertHeaderFromCookie(@CookieValue("accessToken") String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        return ResponseEntity.ok()
                .headers(headers)
                .body(Map.of("loginType", "social", "message", "로그인 성공"));
    }
}
