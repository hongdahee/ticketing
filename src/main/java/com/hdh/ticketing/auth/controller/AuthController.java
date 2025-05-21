package com.hdh.ticketing.auth.controller;

import com.hdh.ticketing.auth.dto.request.UserRequestDto;
import com.hdh.ticketing.auth.dto.response.UserResponseDto;
import com.hdh.ticketing.auth.service.AuthService;
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

//    @PostMapping("/signup")
//    public ResponseEntity<UserResponseDto> signup(@RequestBody UserRequestDto userRequestDto){
//        return ResponseEntity.ok(authService.signup(userRequestDto));
//    }
}
