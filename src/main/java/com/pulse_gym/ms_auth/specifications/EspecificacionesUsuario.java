package com.pulse_gym.ms_auth.specifications;

import com.pulse_gym.lb_common.entity.auth.User;
import com.pulse_gym.lb_common.enums.EnumRol;

import org.springframework.data.jpa.domain.Specification;

public class EspecificacionesUsuario {

    public static Specification<User> tieneEstado(Boolean estado) {
        return (root, query, cb) -> {
            if (estado == null)
                return cb.conjunction();
            return cb.equal(root.get("estado"), estado);
        };
    }

    public static Specification<User> tieneRol(String rol) {
        return (root, query, cb) -> {
            if (rol == null || rol.isBlank())
                return cb.conjunction();
            try {
                EnumRol rolEnum = EnumRol.valueOf(rol.toLowerCase());
                return cb.equal(root.get("rol"), rolEnum);
            } catch (IllegalArgumentException e) {
                return cb.disjunction();
            }
        };
    }

    public static Specification<User> contieneUsername(String username) {
        return (root, query, cb) -> {
            if (username == null || username.isBlank())
                return cb.conjunction();
            return cb.like(cb.lower(root.get("username")), "%" + username.toLowerCase() + "%");
        };
    }

    public static Specification<User> busquedaGeneral(String busqueda) {
        return (root, query, cb) -> {
            if (busqueda == null || busqueda.isBlank())
                return cb.conjunction();
            String patron = "%" + busqueda.toLowerCase() + "%";
            return cb.or(
                cb.like(cb.lower(root.get("username")), patron),
                cb.like(cb.lower(root.get("email")), patron)
            );
        };
    }

    public static Specification<User> contieneEmail(String email) {
        return (root, query, cb) -> {
            if (email == null || email.isBlank())
                return cb.conjunction();
            return cb.like(cb.lower(root.get("email")), "%" + email.toLowerCase() + "%");
        };
    }
}