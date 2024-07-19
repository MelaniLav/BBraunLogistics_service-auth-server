package com.bbraun.serviceauthserver.repository;

import com.bbraun.serviceauthserver.models.entity.Rol;
import com.bbraun.serviceauthserver.models.entity.RolName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RolRepository extends JpaRepository<Rol,Integer> {
    Optional<Rol> findByRol(RolName rolName);
}
