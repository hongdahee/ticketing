package com.hdh.ticketing.auth.controller;

import com.hdh.ticketing.auth.dto.request.UserAuthRequestDto;
import com.hdh.ticketing.auth.dto.response.UserAuthResponseDto;
import com.hdh.ticketing.auth.service.AuthService;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import com.hdh.ticketing.security.jwt.dto.request.TokenRequestDto;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<UserAuthResponseDto> signup(@RequestBody UserAuthRequestDto userAuthRequestDto){
        return ResponseEntity.ok(authService.signup(userAuthRequestDto));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody UserAuthRequestDto userAuthRequestDto,
                                          HttpServletResponse response){
        TokenDto tokenDto = authService.login(userAuthRequestDto);
        response.setHeader("Authorization", "Bearer " + tokenDto.getAccessToken());
        response.setHeader("X-Refresh-Token", tokenDto.getRefreshToken());

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("message", "로그인에 성공했습니다.");
        responseBody.put("loginType", "local");
        return ResponseEntity.ok(responseBody);
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenDto> reissue(@RequestBody TokenRequestDto tokenRequestDto){
        return ResponseEntity.ok(authService.reissue(tokenRequestDto));
    }

    @GetMapping("/auth/convert")
    public ResponseEntity<?> convertHeaderFromCookie(@CookieValue("accessToken") String accessToken,
                                                     @CookieValue("refreshToken") String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.add("X-Refresh-Token", refreshToken);

        return ResponseEntity.ok()
                .headers(headers)
                .body(Map.of("loginType", "social", "message", "로그인 성공"));
    }
}
