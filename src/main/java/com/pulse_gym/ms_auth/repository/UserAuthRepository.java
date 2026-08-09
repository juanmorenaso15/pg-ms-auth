package com.pulse_gym.ms_auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.pulse_gym.lb_common.entity.auth.User;

import feign.Param;

public interface UserAuthRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    /**
     * Busca un usuario por su email.
     *
     * @param email El email del usuario
     * @return El usuario si existe, o vacío si no se encuentra
     */
    Optional<User> findByEmail(String email);

    /**
     * Busca un usuario por su nombre de usuario.
     *
     * @param username El nombre de usuario
     * @return El usuario si existe, o vacío si no se encuentra
     */
    Optional<User> findByUsername(String username);

    /**
     * Busca los datos de inicio de sesión de un usuario por su email.
     * 
     * @param email El email del usuario
     * @return Un arreglo de objetos que contiene los datos de inicio de sesión del
     *         usuario, o vacío si no se encuentra
     */
    @Query("SELECT u.id, u.password, u.estado, u.failedAttempts, u.lockTime, u.rol, u.email FROM User u WHERE u.email = :email")
    Optional<Object[]> findLoginDataByEmail(@Param("email") String email);

    /**
     * Incrementa el contador de intentos fallidos de inicio de sesión de un usuario y establece el tiempo de bloqueo si se alcanza el máximo de intentos.
     *
     * @param userId      El ID del usuario
     * @param maxAttempts El número máximo de intentos fallidos permitidos
     * @return El número de filas afectadas
     */
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = COALESCE(u.failedAttempts, 0) + 1, u.lockTime = CASE WHEN (COALESCE(u.failedAttempts, 0) + 1) >= :maxAttempts THEN CURRENT_TIMESTAMP ELSE u.lockTime END WHERE u.id = :userId")
    int incrementFailedAttempts(@Param("userId") Long userId, @Param("maxAttempts") int maxAttempts);

    /**
     * Restablece el contador de intentos fallidos de inicio de sesión de un usuario y elimina el tiempo de bloqueo.
     *
     * @param userId El ID del usuario
     * @return El número de filas afectadas
     */
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = 0, u.lockTime = NULL WHERE u.id = :userId")
    int resetFailedAttempts(@Param("userId") Long userId);
}
