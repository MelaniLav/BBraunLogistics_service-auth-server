package com.bbraun.serviceauthserver.service;

import com.bbraun.serviceauthserver.models.dto.CreateUsuarioDTO;
import com.bbraun.serviceauthserver.models.dto.MessageDTO;
import com.bbraun.serviceauthserver.models.entity.Rol;
import com.bbraun.serviceauthserver.models.entity.RolName;
import com.bbraun.serviceauthserver.models.entity.Usuario;
import com.bbraun.serviceauthserver.repository.RolRepository;
import com.bbraun.serviceauthserver.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final PasswordEncoder passwordEncoder;


    public MessageDTO createUser(CreateUsuarioDTO dto){
        Usuario usuario = Usuario.builder()
                .email(dto.email())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Rol> roles = new HashSet<>();

        dto.roles().forEach( r -> {
            Rol rol = rolRepository.findByRol(RolName.valueOf(r))
                    .orElseThrow(() -> new RuntimeException("rol no encontrado"));
            roles.add(rol);
        });

        usuario.setRoles(roles);
        usuarioRepository.save(usuario);
        return new MessageDTO("usuario: "+usuario.getEmail()+ " guardado.");
    }

    public Usuario findByEmail(String email){
        return usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("usuario no encontrado"));
    }
}
