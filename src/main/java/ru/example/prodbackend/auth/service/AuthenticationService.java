package ru.example.prodbackend.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import ru.example.prodbackend.auth.dto.UpdateProfileRequest;
import ru.example.prodbackend.auth.dto.UpdateProfileResponse;
import ru.example.prodbackend.auth.dto.ChangePasswordRequest;
import ru.example.prodbackend.user.service.UserService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.example.prodbackend.auth.dto.AuthenticationRequest;
import ru.example.prodbackend.auth.dto.AuthenticationResponse;
import ru.example.prodbackend.auth.dto.RegisterRequest;
import ru.example.prodbackend.auth.dto.refresh.RefreshTokenRequest;
import ru.example.prodbackend.exception.UserAlreadyExistsException;
import ru.example.prodbackend.exception.UserNotFoundException;
import ru.example.prodbackend.user.entity.UserEntity;
import ru.example.prodbackend.user.entity.UserRole;
import ru.example.prodbackend.user.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    @Transactional
    public UpdateProfileResponse updateProfile(UserEntity principal, UpdateProfileRequest request) {
        UserEntity user = currentUser(principal);
        boolean emailChanged = request.getEmail() != null && !request.getEmail().equals(user.getEmail());
        if (emailChanged && userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with this email already exists");
        }
        user.updateProfile(request.getEmail(), request.getFirstName(), request.getLastName());
        userRepository.saveAndFlush(user);
        UpdateProfileResponse response = UpdateProfileResponse.builder()
                .profile(userService.getProfile(user))
                .build();
        if (emailChanged) {
            refreshTokenService.deleteAllByUser(user);
            response.setAccessToken(jwtService.generateToken(user));
            response.setRefreshToken(refreshTokenService.createRefreshToken(user));
        }
        return response;
    }

    @Transactional
    public void changePassword(UserEntity principal, ChangePasswordRequest request) {
        UserEntity user = currentUser(principal);
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid current password");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.saveAndFlush(user);
        refreshTokenService.deleteAllByUser(user);
    }

    private UserEntity currentUser(UserEntity principal) {
        return userRepository.findById(principal.getId())
                .orElseThrow(() -> new UserNotFoundException("Current user not found"));
    }

    @Transactional
    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with this email already exists");
        }

        UserEntity user = UserEntity.builder()
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .build();

        userRepository.saveAndFlush(user);

        return AuthenticationResponse.builder()
                .accessToken(jwtService.generateToken(user))
                .refreshToken(refreshTokenService.createRefreshToken(user))
                .build();
    }

    @Transactional
    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        UserEntity user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("user with email - " + request.getEmail() + " not found"));


        return AuthenticationResponse.builder()
                .accessToken(jwtService.generateToken(user))
                .refreshToken(refreshTokenService.createRefreshToken(user))
                .build();
    }

    @Transactional
    public AuthenticationResponse updateTokens(RefreshTokenRequest request) {
        String rawToken = request.getRefreshToken();
        UserEntity user = refreshTokenService.getUserByRefreshToken(rawToken);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.rotateRefreshToken(rawToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Transactional
    public void logout(RefreshTokenRequest request) {
        refreshTokenService.revokeRefreshToken(request.getRefreshToken());
    }

    @Transactional
    public void logoutAll(RefreshTokenRequest request) {
        UserEntity user = refreshTokenService.getUserByRefreshToken(request.getRefreshToken());
        refreshTokenService.deleteAllByUser(user);
    }


}
