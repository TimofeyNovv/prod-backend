package ru.example.prodbackend.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import ru.example.prodbackend.user.dto.UserProfileResponse;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileResponse {
    private UserProfileResponse profile;

    @Schema(description = "Новый access токен при изменении email; иначе null")
    private String accessToken;

    @Schema(description = "Новый refresh токен при изменении email; иначе null")
    private String refreshToken;
}
