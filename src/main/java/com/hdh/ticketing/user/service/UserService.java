package com.hdh.ticketing.user.service;

import com.hdh.ticketing.user.domain.SiteUser;
import com.hdh.ticketing.user.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public SiteUser findUserByUserId(Long userId){
        return userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("해당 ID의 사용자를 찾을 수 없습니다: " + userId));
    }

    public SiteUser findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("해당 username의 사용자를 찾을 수 없습니다: " + username));
    }
}
