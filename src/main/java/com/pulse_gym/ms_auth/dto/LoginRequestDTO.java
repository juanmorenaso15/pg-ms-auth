package com.pulse_gym.ms_auth.dto;

import lombok.Data;

@Data
public class LoginRequestDTO {
    
    /**
     * Email del usuario
     */
    private String email;

    /**
     * Contraseña del usuario
     */
    private String password;
}
