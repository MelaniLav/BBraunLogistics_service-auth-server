package com.bbraun.serviceauthserver.controllers;

import com.bbraun.serviceauthserver.models.dto.CreateUsuarioDTO;
import com.bbraun.serviceauthserver.models.dto.MessageDTO;
import com.bbraun.serviceauthserver.models.entity.Usuario;
import com.bbraun.serviceauthserver.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final UsuarioService usuarioService;

    @PostMapping("/create")
    public ResponseEntity<MessageDTO> createUser(@RequestBody CreateUsuarioDTO dto){
        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.createUser(dto));
    }
}
