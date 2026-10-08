package ru.example.prodbackend.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.example.prodbackend.user.dto.UserProfileResponse;
import ru.example.prodbackend.user.entity.UserEntity;

@Service
@RequiredArgsConstructor
public class UserService {
    public UserProfileResponse getProfile(UserEntity user) {
        return UserProfileResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }
}
