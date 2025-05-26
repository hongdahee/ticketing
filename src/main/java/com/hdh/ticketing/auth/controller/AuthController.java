package com.hdh.ticketing.auth.controller;

import com.hdh.ticketing.auth.dto.request.LogoutRequestDto;
import com.hdh.ticketing.auth.dto.request.UserAuthRequestDto;
import com.hdh.ticketing.auth.dto.response.UserAuthResponseDto;
import com.hdh.ticketing.auth.service.AuthService;
import com.hdh.ticketing.security.jwt.dto.TokenDto;
import com.hdh.ticketing.security.jwt.dto.request.TokenRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public ResponseEntity<TokenDto> login(@RequestBody UserAuthRequestDto userAuthRequestDto){
        return ResponseEntity.ok(authService.login(userAuthRequestDto));
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenDto> reissue(@RequestBody TokenRequestDto tokenRequestDto){
        return ResponseEntity.ok(authService.reissue(tokenRequestDto));
    }
}
