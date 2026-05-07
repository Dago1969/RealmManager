package com.qtm.realmmanager.controller;

import com.qtm.realmmanager.service.KeycloakRealmService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller per la creazione di un nuovo realm su Keycloak.
 * Accetta solo il parametro newRealmName e crea anche ruolo e utente di default.
 */
@Slf4j
@RestController
@RequestMapping("/api/realms")
@RequiredArgsConstructor
public class RealmController {

    private final KeycloakRealmService keycloakRealmService;

    @PostMapping
    public ResponseEntity<?> createRealm(@RequestBody Map<String, String> body) {
        String newRealmName = body.get("newRealmName");
        String codeRealm = body.get("codeRealm");
        String rootUrl = body.get("rootUrl");
        if (newRealmName == null || newRealmName.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "newRealmName is required"));
        }
        if (codeRealm == null || codeRealm.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "codeRealm is required"));
        }
        if (rootUrl == null || rootUrl.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "rootUrl is required"));
        }
        // Valori di default
        String defaultRole = "realm-admin";
        String defaultUser = "admin";
        String defaultPassword = "admin";
        try {
            keycloakRealmService.createRealmWithUserAndRole(newRealmName, codeRealm, rootUrl, defaultRole, defaultUser, defaultPassword);
            return ResponseEntity.ok(Map.of(
                "realm", newRealmName,
                "codeRealm", codeRealm,
                "rootUrl", rootUrl,
                "role", defaultRole,
                "user", defaultUser,
                "password", defaultPassword
            ));
        } catch (Exception e) {
            log.error("Errore creazione realm", e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }
}
