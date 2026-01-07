package com.hdh.ticketing.user.controller;

import com.hdh.ticketing.user.domain.SiteUser;
import com.hdh.ticketing.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

//@RestController
//@RequiredArgsConstructor
//public class UserController {
//
//    private final UserService userService;
//
//    @GetMapping("/{id}")
//    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long id){
//        SiteUser user = userService.findUserById(id);
//        UserResponseDto
//        return ResponseEntity.ok(userDto);
//    }
//
//}
