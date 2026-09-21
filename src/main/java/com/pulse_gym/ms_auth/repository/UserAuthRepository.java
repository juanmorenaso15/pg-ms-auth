package com.pulse_gym.ms_auth.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.pulse_gym.lb_common.entity.auth.User;

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
     * 
     * @param email
     * @param username
     * @return
     */
    @Query("SELECT u.email, u.username FROM User u WHERE u.email = :email OR u.username = :username")
    Optional<List<Object[]>> checkDuplicates(@Param("email") String email, @Param("username") String username);

    /**
     * 
     * @return
     */
    @Query("SELECT COUNT(u) FROM User u")
    long contarTotalUsuarios();

    /**
     * 
     * @return
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.estado = true")
    long contarUsuariosActivos();

    /**
     * 
     * @return
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.estado = false OR u.estado IS NULL")
    long contarUsuariosInactivos();

    /**
     * 
     * @param inicioMes
     * @return
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.fechaRegistro >= :inicioMes")
    long contarNuevosDesde(@Param("inicioMes") java.time.LocalDateTime inicioMes);
}
