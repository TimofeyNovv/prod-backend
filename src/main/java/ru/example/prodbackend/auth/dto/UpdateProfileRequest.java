package ru.example.prodbackend.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import jakarta.validation.constraints.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequest {
    @Size(max = 255, message = "email is too long")
    @Email
    @Schema(description = "Новый email; null сохраняет текущее значение")
    private String email;

    @Size(max = 255)
    @Schema(description = "Имя; null сохраняет значение, пустая строка удаляет его")
    private String firstName;

    @Size(max = 255)
    @Schema(description = "Фамилия; null сохраняет значение, пустая строка удаляет его")
    private String lastName;
}
