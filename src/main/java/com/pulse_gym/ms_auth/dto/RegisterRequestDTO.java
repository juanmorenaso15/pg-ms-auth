package com.pulse_gym.ms_auth.dto;

import com.pulse_gym.lb_common.enums.EnumRol;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequestDTO {

    /**
     * Email del usuario
     */
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe tener un formato válido")
    private String email;

    /**
     * Contraseña del usuario
     */
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
    private String password;

    /**
     * Nombre de usuario (username)
     */
    @NotBlank(message = "El nombre de usuario es obligatorio")
    @Size(min = 3, max = 50, message = "El nombre de usuario debe tener entre 3 y 50 caracteres")
    private String username;

    /**
     * Rol del usuario
     */
    @NotNull(message = "El rol es obligatorio")
    private EnumRol rol;

    /**
     * Estado del usuario
     */
    @NotNull(message = "El estado es obligatorio")
    private Boolean estado;
}