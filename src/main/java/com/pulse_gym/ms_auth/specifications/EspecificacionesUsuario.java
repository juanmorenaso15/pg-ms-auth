package com.pulse_gym.ms_auth.specifications;

import com.pulse_gym.lb_common.entity.auth.User;
import com.pulse_gym.lb_common.enums.EnumRol;

import org.springframework.data.jpa.domain.Specification;

public class EspecificacionesUsuario {

    public static Specification<User> tieneEstado(Boolean estado) {
        return (root, query, cb) -> {
            if (estado == null) return cb.conjunction();
            return cb.equal(root.get("estado"), estado);
        };
    }

    public static Specification<User> tieneRol(String rol) {
        return (root, query, cb) -> {
            if (rol == null || rol.isBlank()) return cb.conjunction();
            try {
                EnumRol rolEnum = EnumRol.valueOf(rol.toLowerCase());
                return cb.equal(root.get("rol"), rolEnum);
            } catch (IllegalArgumentException e) {
                return cb.disjunction(); // nunca se cumple
            }
        };
    }
}