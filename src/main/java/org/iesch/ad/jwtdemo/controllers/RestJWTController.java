package org.iesch.ad.jwtdemo.controllers;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.extern.slf4j.Slf4j;
import org.iesch.ad.jwtdemo.services.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
public class RestJWTController {

    @Autowired
    JWTService jwtService;

    @GetMapping("/public/generate")
    public ResponseEntity<?> generate(){
        String jwt = jwtService.createJWT();
        Map<String, String> contenido = new HashMap<>();
        contenido.put("jwt", jwt);
        return ResponseEntity.ok(contenido);
    }

    @GetMapping("/public/check")
    public ResponseEntity<?> check (@RequestParam String jwt){
        Jws<Claims> ourJWT = jwtService.parseJWT(jwt);
        return ResponseEntity.ok(ourJWT);
    }

    @GetMapping("/admin")
    public ResponseEntity<?> getAdminMessage(){
        //si no va Authentication --> var
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("Datos del usuario: {}", auth.getPrincipal());
        log.info("Datos de los permisos: {}", auth.getAuthorities());
        log.info("¿Autenticado?: {}", auth.isAuthenticated());

        Map<String, String> message = new HashMap<>();
        message.put("Contenido", "Mensaje que solo un admin puede ver");
        return ResponseEntity.ok(message);
    }

}
