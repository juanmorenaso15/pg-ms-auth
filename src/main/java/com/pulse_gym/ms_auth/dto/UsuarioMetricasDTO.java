package com.pulse_gym.ms_auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UsuarioMetricasDTO {
    
    /** */
    private long totalUsuarios;
    
    /** */
    private long usuariosActivos;
    
    /** */
    private long usuariosInactivos;
    
    /** */
    private long nuevosEsteMes;
}