package com.pulse_gym.ms_auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.pulse_gym.lb_common.entity.auth.PasswordResetToken;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    /**
     * Busca un token de recuperación por su valor.
     *
     * @param token El token de recuperación
     * @return El token si existe, o vacío si no se encuentra
     */
    Optional<PasswordResetToken> findByToken(String token);

    /**
     * Elimina todos los tokens de recuperación de un usuario.
     *
     * @param userId El ID del usuario
     */
    void deleteByUserId(Long userId);
}