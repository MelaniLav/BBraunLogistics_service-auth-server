package com.bbraun.serviceauthserver.models.dto;

import com.bbraun.serviceauthserver.models.entity.Rol;

import java.util.List;

public record CreateUsuarioDTO (
        String email,
        String password,
        List<String> roles){ }
