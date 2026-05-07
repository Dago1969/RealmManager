package com.qtm.realmmanager.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.*;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.core.Response;
import java.util.Collections;

/**
 * Service per la gestione di realm, ruoli e utenti su Keycloak tramite Admin Client.
 * Permette di creare un nuovo realm, un ruolo e un utente, e assegnare il ruolo all'utente.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakRealmService {

    // Configurare questi parametri secondo il proprio Keycloak
    private final String serverUrl = "http://localhost:8085";
    private final String masterRealm = "master";
    private final String adminUsername = "admin";
    private final String adminPassword = "admin";
    private final String adminClientId = "admin-cli";

    private Keycloak keycloak;

    @PostConstruct
    public void init() {
        keycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(masterRealm)
                .clientId(adminClientId)
                .username(adminUsername)
                .password(adminPassword)
                .grantType(OAuth2Constants.PASSWORD)
                .build();
    }

    /**
     * Crea un nuovo realm, clona un client, crea ruoli e utente, e assegna i ruoli.
     * @param realmName nome del nuovo realm
     * @param codeRealm codice realm per nome client
     * @param rootUrl rootUrl del client
     * @param roleName nome del ruolo da creare (default)
     * @param username nome utente
     * @param password password utente
     */
    public void createRealmWithUserAndRole(String realmName, String codeRealm, String rootUrl, String roleName, String username, String password) {
        // 1. Crea il realm
        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(realmName);
        realm.setEnabled(true);
        keycloak.realms().create(realm);
        log.info("Realm creato: {}", realmName);

        // 2. Clona il client app-cliente-A dal realm QTM
        ClientRepresentation sourceClient = keycloak.realm("QTM").clients().findByClientId("app-cliente-A").stream().findFirst().orElse(null);
        if (sourceClient == null) {
            throw new RuntimeException("Client sorgente app-cliente-A non trovato nel realm QTM");
        }
        ClientRepresentation newClient = new ClientRepresentation();
        newClient.setClientId(codeRealm + "-A");
        newClient.setName(codeRealm + "-A");
        newClient.setRootUrl(rootUrl);
        newClient.setEnabled(sourceClient.isEnabled());
        newClient.setProtocol(sourceClient.getProtocol());
        newClient.setPublicClient(sourceClient.isPublicClient());
        newClient.setRedirectUris(sourceClient.getRedirectUris());
        newClient.setBaseUrl(sourceClient.getBaseUrl());
        newClient.setAdminUrl(sourceClient.getAdminUrl());
        newClient.setWebOrigins(sourceClient.getWebOrigins());
        newClient.setAttributes(sourceClient.getAttributes());
        newClient.setDefaultRoles(sourceClient.getDefaultRoles());
        newClient.setBearerOnly(sourceClient.isBearerOnly());
        newClient.setDirectAccessGrantsEnabled(sourceClient.isDirectAccessGrantsEnabled());
        newClient.setServiceAccountsEnabled(sourceClient.isServiceAccountsEnabled());
        newClient.setStandardFlowEnabled(sourceClient.isStandardFlowEnabled());
        newClient.setImplicitFlowEnabled(sourceClient.isImplicitFlowEnabled());
        // newClient.setAuthorizationServicesEnabled(...) non esiste su ClientRepresentation nelle versioni Keycloak 22+
        newClient.setClientAuthenticatorType(sourceClient.getClientAuthenticatorType());
        // ... copia altri campi rilevanti se necessario ...
        keycloak.realm(realmName).clients().create(newClient);
        log.info("Client clonato e creato: {}", codeRealm + "-A");

        // 3. Crea i ruoli richiesti
        String[][] roles = {
            {"Admin_QTM", "Amministratore QTM"},
            {"Doctor-HospitalReferent", "Medico Ospedaliero QTM"},
            {"Nurse_QTM", "Infermiere QTM"},
            {"Operator_QTM", "Operatore QTM"}
        };
        for (String[] r : roles) {
            RoleRepresentation role = new RoleRepresentation();
            role.setName(r[0]);
            role.setDescription(r[1]);
            keycloak.realm(realmName).roles().create(role);
            log.info("Ruolo creato: {} - {}", r[0], r[1]);
        }

        // 4. Recupera o crea l'utente francesco.tripodi
        String userId = null;
        var users = keycloak.realm(realmName).users().search("francesco.tripodi", true);
        if (users != null && !users.isEmpty()) {
            userId = users.get(0).getId();
            log.info("Utente francesco.tripodi già esistente (ID: {})", userId);
        } else {
            UserRepresentation user = new UserRepresentation();
            user.setUsername("francesco.tripodi");
            user.setEmail("francesco.tripodi@gmail.com");
            user.setFirstName("Francesco Maria");
            user.setLastName("Tripodi");
            user.setEnabled(true);
            Response response = keycloak.realm(realmName).users().create(user);
            userId = CreatedResponseUtil.getCreatedId(response);
            log.info("Utente creato: {} (ID: {})", "francesco.tripodi", userId);
            // Imposta la password solo se creato ora
            CredentialRepresentation passwordCred = new CredentialRepresentation();
            passwordCred.setTemporary(false);
            passwordCred.setType(CredentialRepresentation.PASSWORD);
            passwordCred.setValue("Qtm!2026");
            keycloak.realm(realmName).users().get(userId).resetPassword(passwordCred);
            log.info("Password impostata per utente: {}", "francesco.tripodi");
        }

        // 5. Associa tutti i ruoli all'utente francesco.tripodi
        for (String[] r : roles) {
            RoleRepresentation realmRole = keycloak.realm(realmName).roles().get(r[0]).toRepresentation();
            keycloak.realm(realmName).users().get(userId).roles().realmLevel().add(Collections.singletonList(realmRole));
            log.info("Ruolo {} assegnato all'utente {}", r[0], "francesco.tripodi");
        }

        // (Eliminato: duplicazione creazione ruolo/utente/password, ora gestito solo con i dati richiesti dal prompt)
    }
}
