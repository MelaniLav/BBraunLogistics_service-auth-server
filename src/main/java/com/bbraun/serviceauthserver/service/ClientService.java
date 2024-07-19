package com.bbraun.serviceauthserver.service;

import com.bbraun.serviceauthserver.models.dto.CreateClientDTO;
import com.bbraun.serviceauthserver.models.dto.MessageDTO;
import com.bbraun.serviceauthserver.models.entity.Client;
import com.bbraun.serviceauthserver.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public void save(RegisteredClient registeredClient) {

    }

    public MessageDTO create(CreateClientDTO dto){
        Client client = clientFromDto(dto);
        clientRepository.save(client);
        return new MessageDTO("client: "+client.getClientId()+ " guardado");
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findByClientId(id).orElseThrow(()-> new RuntimeException("client no encontrado"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId).orElseThrow(()-> new RuntimeException("client no encontrado"));
        return Client.toRegisteredClient(client);
    }

    private Client clientFromDto(CreateClientDTO dto){
        Client client = Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .postLogoutRedirectUris(dto.getPostLogoutRedirectUris())
                .scopes(dto.getScopes())
                .requireProofKey(dto.isRequireProofKey())
                .build();
        return client;
    }

}
