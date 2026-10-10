package ru.example.prodbackend.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import ru.example.prodbackend.user.entity.UserEntity;
import ru.example.prodbackend.auth.dto.UpdateProfileRequest;
import ru.example.prodbackend.auth.dto.UpdateProfileResponse;
import ru.example.prodbackend.auth.dto.ChangePasswordRequest;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.example.prodbackend.auth.dto.AuthenticationRequest;
import ru.example.prodbackend.auth.dto.AuthenticationResponse;
import ru.example.prodbackend.auth.dto.RegisterRequest;
import ru.example.prodbackend.auth.dto.refresh.RefreshTokenRequest;
import ru.example.prodbackend.auth.service.AuthenticationService;
import ru.example.prodbackend.exception.dto.ErrorResponse;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Operation(
            summary = "регистрация пользователя",
            description = "создает пользователя и возвращает пару access и refresh токенов",
            responses = {
                    @ApiResponse(responseCode = "200", description = "успешно, пользователь создан, возвращается пара токенов"),
                    @ApiResponse(responseCode = "400", description = "тело запроса отсутствует или содержит некорректный JSON", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "409", description = "пользователь с таким email уже существует", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "поля запроса не прошли валидацию", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            }
    )
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authenticationService.register(request));
    }


    @Operation(
            summary = "вход в аккаунт",
            description = "проверяет email и пароль и возвращает пару access и refresh токенов",
            responses = {
                    @ApiResponse(responseCode = "200", description = "успешно, возвращается пара токенов"),
                    @ApiResponse(responseCode = "400", description = "тело запроса отсутствует или содержит некорректный JSON", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "401", description = "неверный email или пароль", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "404", description = "пользователь не найден после проверки учетных данных", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "поля запроса не прошли валидацию", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            }
    )
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @Valid @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @Operation(
            summary = "получение новой пары токенов",
            description = "принимает refresh токен и возвращает новую пару токенов. старый refresh токен больше не работает",
            responses = {
                    @ApiResponse(responseCode = "200", description = "успешно, возвращается два новых токена"),
                    @ApiResponse(responseCode = "400", description = "тело запроса отсутствует или содержит некорректный JSON", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "401", description = "refresh токен некорректный, истек или уже был заменен", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "поля запроса не прошли валидацию", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            }
    )
    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        return ResponseEntity.ok(authenticationService.updateTokens(request));
    }

    @Operation(
            summary = "выход из аккаунта",
            description = "удаляет refresh токен текущего устройства. сессии остальных устройств сохраняются",
            responses = {
                    @ApiResponse(responseCode = "204", description = "успешно, refresh токен удален или уже отсутствует", content = @Content),
                    @ApiResponse(responseCode = "400", description = "тело запроса отсутствует или содержит некорректный JSON", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "поля запроса не прошли валидацию", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            }
    )
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        authenticationService.logout(request);
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "выход со всех устройств",
            description = "принимает действующий refresh токен и удаляет все refresh токены пользователя",
            responses = {
                    @ApiResponse(responseCode = "204", description = "успешно, все refresh токены пользователя удалены", content = @Content),
                    @ApiResponse(responseCode = "400", description = "тело запроса отсутствует или содержит некорректный JSON", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "401", description = "refresh токен некорректный или истек", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "поля запроса не прошли валидацию", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            }
    )
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        authenticationService.logoutAll(request);

        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "редактирование профиля текущего пользователя",
            description = "Изменяет email, имя и фамилию. При изменении email отзывает все refresh токены и возвращает новую пару; клиент должен сразу использовать новые токены.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Профиль обновлен", content = @Content(schema = @Schema(implementation = UpdateProfileResponse.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректное тело запроса", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Требуется действующий access токен", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "409", description = "Email уже занят", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "Ошибка валидации", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            })
    @SecurityRequirement(name = "jwtAuth")
    @PatchMapping("/profile")
    public ResponseEntity<UpdateProfileResponse> updateProfile(
            @AuthenticationPrincipal UserEntity user, @Valid @RequestBody UpdateProfileRequest request) {
        return ResponseEntity.ok(authenticationService.updateProfile(user, request));
    }

    @Operation(summary = "изменение пароля текущего пользователя",
            description = "Проверяет текущий пароль и отзывает все refresh токены. Access токены сохраняются до истечения срока действия.",
            responses = {
                    @ApiResponse(responseCode = "204", description = "Пароль изменен", content = @Content),
                    @ApiResponse(responseCode = "400", description = "Некорректное тело запроса", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Некорректный access токен или текущий пароль", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
                    @ApiResponse(responseCode = "422", description = "Ошибка валидации", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
            })
    @SecurityRequirement(name = "jwtAuth")
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal UserEntity user, @Valid @RequestBody ChangePasswordRequest request) {
        authenticationService.changePassword(user, request);
        return ResponseEntity.noContent().build();
    }
}
