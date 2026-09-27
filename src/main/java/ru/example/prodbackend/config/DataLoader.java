package ru.example.prodbackend.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.example.prodbackend.auth.service.RefreshTokenService;
import ru.example.prodbackend.user.entity.UserEntity;
import ru.example.prodbackend.user.entity.UserRole;
import ru.example.prodbackend.user.repository.UserRepository;

@Slf4j
@Component
@Profile({"dev", "prod"})
@RequiredArgsConstructor
public class DataLoader implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    @Value("${ADMIN_PASSWORD}")
    private String adminPassword;

    @Value("${USER1_PASSWORD}")
    private String user1Password;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        createUser("admin", adminPassword, UserRole.ADMIN);
        createUser("user1", user1Password, UserRole.USER);

        log.info(
                "Demo data loaded: admin and user1, one refresh session per user"
        );
    }

    private void createUser(
            String email,
            String password,
            UserRole role
    ) {
        UserEntity user = UserEntity.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(role)
                .build();

        userRepository.saveAndFlush(user);

        refreshTokenService.createRefreshToken(user);
    }
}