package ru.example.prodbackend.user.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.example.prodbackend.exception.dto.ErrorResponse;
import ru.example.prodbackend.user.dto.UserProfileResponse;
import ru.example.prodbackend.user.entity.UserEntity;
import ru.example.prodbackend.user.service.UserService;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @Operation(
            summary = "получение профиля текущего пользователя",
            description = "возвращает идентификатор, email и роль пользователя, авторизованного по access токену",
            responses = {
                    @ApiResponse(responseCode = "200", description = "успешно, возвращается профиль текущего пользователя", content = @Content(schema = @Schema(implementation = UserProfileResponse.class))),
                    @ApiResponse(responseCode = "401", description = "access токен отсутствует, некорректный или истек", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            }
    )
    @SecurityRequirement(name = "jwtAuth")
    @GetMapping("/me")
    ResponseEntity<UserProfileResponse> getProfile(@AuthenticationPrincipal UserEntity user) {
        return ResponseEntity.ok(userService.getProfile(user));
    }
}
