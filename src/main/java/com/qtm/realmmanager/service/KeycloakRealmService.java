package com.qtm.realmmanager.service;

import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Service per la gestione di realm, ruoli e utenti su Keycloak tramite Admin Client.
 * Permette di creare un nuovo realm, un ruolo e un utente, e assegnare il ruolo all'utente.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakRealmService {

    private static final String REALM_MANAGEMENT_CLIENT_ID = "realm-management";
    private static final List<String> DEFAULT_ADMIN_HELPER_ROLE_NAMES = List.of(
            "query-clients",
            "query-users",
            "query-realms",
            "view-clients",
            "view-users",
            "view-realm",
            "view-authorization",
            "manage-clients",
            "manage-users"
    );

    @Value("${app.keycloak.server-url:http://localhost:8085}")
    private String serverUrl;

    @Value("${app.keycloak.master-realm:master}")
    private String masterRealm;

    @Value("${app.keycloak.admin-username:admin}")
    private String adminUsername;

    @Value("${app.keycloak.admin-password:admin}")
    private String adminPassword;

    @Value("${app.keycloak.admin-client-id:admin-cli}")
    private String adminClientId;

    @Value("${app.keycloak.template-realm:QTM}")
    private String templateRealm;

    @Value("${app.keycloak.provisioning-client-id:admin-cli-helper}")
    private String provisioningClientId;

    @Value("${app.keycloak.provisioning-client-secret:Q5VQ0pWS6lS5N29u0xha5zodJ1LDM19h}")
    private String provisioningClientSecret;

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

        // Importa il client postman-client se non esiste già (DOPO la creazione del realm)
        if (keycloak.realm(realmName).clients().findByClientId("postman-client").isEmpty()) {
            ClientRepresentation postmanClient = new ClientRepresentation();
            postmanClient.setClientId("postman-client");
            postmanClient.setName("postman-client");
            postmanClient.setDescription("");
            postmanClient.setRootUrl("");
            postmanClient.setAdminUrl("");
            postmanClient.setBaseUrl("");
            postmanClient.setSurrogateAuthRequired(false);
            postmanClient.setEnabled(true);
            postmanClient.setAlwaysDisplayInConsole(false);
            postmanClient.setClientAuthenticatorType("client-secret");
            postmanClient.setRedirectUris(java.util.List.of("/*"));
            postmanClient.setWebOrigins(java.util.List.of("/*"));
            postmanClient.setNotBefore(0);
            postmanClient.setBearerOnly(false);
            postmanClient.setConsentRequired(false);
            postmanClient.setStandardFlowEnabled(true);
            postmanClient.setImplicitFlowEnabled(false);
            postmanClient.setDirectAccessGrantsEnabled(true);
            postmanClient.setServiceAccountsEnabled(false);
            postmanClient.setPublicClient(true);
            postmanClient.setFrontchannelLogout(true);
            postmanClient.setProtocol("openid-connect");
            java.util.Map<String, String> attrs = new java.util.HashMap<>();
            attrs.put("realm_client", "false");
            attrs.put("logout.confirmation.enabled", "false");
            attrs.put("oidc.ciba.grant.enabled", "false");
            attrs.put("client.secret.creation.time", "1775416691");
            attrs.put("backchannel.logout.session.required", "true");
            attrs.put("standard.token.exchange.enabled", "false");
            attrs.put("oauth2.jwt.authorization.grant.enabled", "false");
            attrs.put("frontchannel.logout.session.required", "true");
            attrs.put("oauth2.device.authorization.grant.enabled", "false");
            attrs.put("display.on.consent.screen", "false");
            attrs.put("backchannel.logout.revoke.offline.tokens", "false");
            attrs.put("dpop.bound.access.tokens", "false");
            postmanClient.setAttributes(attrs);
            postmanClient.setFullScopeAllowed(true);
            postmanClient.setNodeReRegistrationTimeout(-1);
            postmanClient.setDefaultClientScopes(java.util.List.of(
                "web-origins", "acr", "roles", "profile", "basic", "email"
            ));
            postmanClient.setOptionalClientScopes(java.util.List.of(
                "address", "phone", "organization", "offline_access", "microprofile-jwt"
            ));
            keycloak.realm(realmName).clients().create(postmanClient);
            log.info("Client postman-client importato nel realm {}", realmName);
        }
        // (già creato sopra)

        // Prepara il client tecnico usato dal provisioning utenti di QTMDashboard.
        ensureProvisioningAdminClient(realmName);

        // 2. Clona il client app-cliente-A dal realm QTM
        ClientRepresentation sourceClient = keycloak.realm(templateRealm).clients().findByClientId("app-cliente-A").stream().findFirst().orElse(null);
        if (sourceClient == null) {
            throw new RuntimeException("Client sorgente app-cliente-A non trovato nel realm " + templateRealm);
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

        // 3. Crea i ruoli richiesti sia a livello realm che client
        String[][] roles = {
            {"Admin_QTM", "Amministratore QTM"},
            {"Nurse_QTM", "Infermiere QTM"},
            {"Operator_QTM", "Operatore QTM"},
            {"Doctor-HospitalReferent", "Medico Ospedaliero Referente"},
            {"SUPER_ADMIN", "SUPER_ADMIN"}
        };
        // Realm-level
        for (String[] r : roles) {
            RoleRepresentation role = new RoleRepresentation();
            role.setName(r[0]);
            role.setDescription(r[1]);
            keycloak.realm(realmName).roles().create(role);
            log.info("Ruolo realm-level creato: {} - {}", r[0], r[1]);
        }
        // Client-level
        String clientId = codeRealm + "-A";
        var clientList = keycloak.realm(realmName).clients().findByClientId(clientId);
        if (clientList == null || clientList.isEmpty()) {
            throw new RuntimeException("Client appena creato non trovato per aggiunta ruoli client-level");
        }
        String createdClientUuid = clientList.get(0).getId();
        for (String[] r : roles) {
            RoleRepresentation clientRole = new RoleRepresentation();
            clientRole.setName(r[0]);
            clientRole.setDescription(r[1]);
            keycloak.realm(realmName).clients().get(createdClientUuid).roles().create(clientRole);
            log.info("Ruolo client-level creato: {} - {}", r[0], r[1]);
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
            // Realm-level
            RoleRepresentation realmRole = keycloak.realm(realmName).roles().get(r[0]).toRepresentation();
            keycloak.realm(realmName).users().get(userId).roles().realmLevel().add(Collections.singletonList(realmRole));
            log.info("Ruolo realm-level {} assegnato all'utente {}", r[0], "francesco.tripodi");
            // Client-level
            RoleRepresentation clientRole = keycloak.realm(realmName).clients().get(createdClientUuid).roles().get(r[0]).toRepresentation();
            keycloak.realm(realmName).users().get(userId).roles().clientLevel(createdClientUuid).add(Collections.singletonList(clientRole));
            log.info("Ruolo client-level {} assegnato all'utente {}", r[0], "francesco.tripodi");
        }

        // (Eliminato: duplicazione creazione ruolo/utente/password, ora gestito solo con i dati richiesti dal prompt)
    }

    private void ensureProvisioningAdminClient(String realmName) {
        ClientRepresentation sourceClient = findClient(templateRealm, provisioningClientId);
        ClientRepresentation targetClient = findClient(realmName, provisioningClientId);

        if (targetClient == null) {
            ClientRepresentation newClient = buildProvisioningClientRepresentation(sourceClient);
            keycloak.realm(realmName).clients().create(newClient);
            log.info("Client {} creato nel realm {}", provisioningClientId, realmName);
            targetClient = findClient(realmName, provisioningClientId);
        } else {
            ClientResource targetClientResource = keycloak.realm(realmName).clients().get(targetClient.getId());
            ClientRepresentation targetRepresentation = targetClientResource.toRepresentation();
            applyProvisioningClientSettings(targetRepresentation, sourceClient);
            targetClientResource.update(targetRepresentation);
            log.info("Client {} aggiornato nel realm {}", provisioningClientId, realmName);
        }

        if (targetClient == null) {
            throw new RuntimeException("Client provisioning non trovato dopo la creazione: " + provisioningClientId);
        }

        synchronizeProvisioningServiceAccountRoles(realmName, sourceClient, targetClient);
    }

    private ClientRepresentation buildProvisioningClientRepresentation(ClientRepresentation sourceClient) {
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        applyProvisioningClientSettings(clientRepresentation, sourceClient);
        return clientRepresentation;
    }

    private void applyProvisioningClientSettings(ClientRepresentation targetClient, ClientRepresentation sourceClient) {
        Map<String, String> sourceAttributes = sourceClient != null && sourceClient.getAttributes() != null
                ? sourceClient.getAttributes()
                : Map.of();

        targetClient.setClientId(provisioningClientId);
        targetClient.setName(provisioningClientId);
        targetClient.setDescription(provisioningClientId);
        targetClient.setProtocol("openid-connect");
        targetClient.setEnabled(true);
        targetClient.setPublicClient(false);
        targetClient.setBearerOnly(false);
        targetClient.setConsentRequired(false);
        targetClient.setStandardFlowEnabled(false);
        targetClient.setImplicitFlowEnabled(false);
        targetClient.setDirectAccessGrantsEnabled(false);
        targetClient.setServiceAccountsEnabled(true);
        targetClient.setFrontchannelLogout(true);
        targetClient.setClientAuthenticatorType("client-secret");
        targetClient.setSecret(provisioningClientSecret);
        targetClient.setRedirectUris(new ArrayList<>());
        targetClient.setWebOrigins(new ArrayList<>());
        targetClient.setBaseUrl(null);
        targetClient.setAdminUrl(null);
        targetClient.setRootUrl(null);
        targetClient.setDefaultClientScopes(sourceClient != null && sourceClient.getDefaultClientScopes() != null
                ? sourceClient.getDefaultClientScopes()
                : List.of("web-origins", "acr", "roles", "profile", "basic", "email"));
        targetClient.setOptionalClientScopes(sourceClient != null && sourceClient.getOptionalClientScopes() != null
                ? sourceClient.getOptionalClientScopes()
                : List.of("address", "phone", "organization", "offline_access", "microprofile-jwt"));
        targetClient.setAttributes(new HashMap<>(sourceAttributes));
        targetClient.getAttributes().put("realm_client", "false");
        targetClient.getAttributes().put("client.secret.creation.time", String.valueOf(System.currentTimeMillis() / 1000));
    }

    private void synchronizeProvisioningServiceAccountRoles(String realmName,
                                                           ClientRepresentation sourceClient,
                                                           ClientRepresentation targetClient) {
        ClientRepresentation targetRealmManagementClient = requireClient(realmName, REALM_MANAGEMENT_CLIENT_ID);
        UserRepresentation targetServiceAccount = keycloak.realm(realmName)
                .clients()
                .get(targetClient.getId())
                .getServiceAccountUser();

        List<RoleRepresentation> currentRoles = keycloak.realm(realmName)
                .users()
                .get(targetServiceAccount.getId())
                .roles()
                .clientLevel(targetRealmManagementClient.getId())
                .listAll();

        // Garantisce sempre il set minimo necessario al provisioning utenti, anche se il realm template
        // o il client sorgente hanno una configurazione parziale o non aggiornata.
        Set<String> desiredRoleNames = new LinkedHashSet<>(DEFAULT_ADMIN_HELPER_ROLE_NAMES);
        desiredRoleNames.addAll(resolveProvisioningRoleNamesFromTemplate(sourceClient));

        Map<String, RoleRepresentation> targetRolesByName = keycloak.realm(realmName)
                .clients()
                .get(targetRealmManagementClient.getId())
                .roles()
                .list()
                .stream()
                .filter(Objects::nonNull)
                .collect(java.util.stream.Collectors.toMap(RoleRepresentation::getName, role -> role, (left, right) -> left));

        Set<String> currentRoleNames = currentRoles.stream()
                .map(RoleRepresentation::getName)
                .filter(Objects::nonNull)
                .collect(java.util.stream.Collectors.toSet());

        List<RoleRepresentation> rolesToAssign = desiredRoleNames.stream()
                .filter(targetRolesByName::containsKey)
                .filter(roleName -> !currentRoleNames.contains(roleName))
                .map(targetRolesByName::get)
                .toList();

        if (!rolesToAssign.isEmpty()) {
            keycloak.realm(realmName)
                    .users()
                    .get(targetServiceAccount.getId())
                    .roles()
                    .clientLevel(targetRealmManagementClient.getId())
                    .add(rolesToAssign);
            log.info("Ruoli realm-management assegnati al service account di {} nel realm {}: {}",
                    provisioningClientId,
                    realmName,
                    rolesToAssign.stream().map(RoleRepresentation::getName).toList());
        }
    }

    private List<String> resolveProvisioningRoleNamesFromTemplate(ClientRepresentation sourceClient) {
        if (sourceClient == null || sourceClient.getId() == null) {
            return List.of();
        }

        ClientRepresentation sourceRealmManagementClient = findClient(templateRealm, REALM_MANAGEMENT_CLIENT_ID);
        if (sourceRealmManagementClient == null) {
            return List.of();
        }

        UserRepresentation sourceServiceAccount = keycloak.realm(templateRealm)
                .clients()
                .get(sourceClient.getId())
                .getServiceAccountUser();

        if (sourceServiceAccount == null) {
            return List.of();
        }

        return keycloak.realm(templateRealm)
                .users()
                .get(sourceServiceAccount.getId())
                .roles()
                .clientLevel(sourceRealmManagementClient.getId())
                .listAll()
                .stream()
                .map(RoleRepresentation::getName)
                .filter(Objects::nonNull)
                .toList();
    }

    private ClientRepresentation requireClient(String realmName, String clientId) {
        ClientRepresentation clientRepresentation = findClient(realmName, clientId);
        if (clientRepresentation == null) {
            throw new RuntimeException("Client " + clientId + " non trovato nel realm " + realmName);
        }
        return clientRepresentation;
    }

    private ClientRepresentation findClient(String realmName, String clientId) {
        return keycloak.realm(realmName)
                .clients()
                .findByClientId(clientId)
                .stream()
                .findFirst()
                .orElse(null);
    }
}
