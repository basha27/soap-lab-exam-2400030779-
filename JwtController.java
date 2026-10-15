package com.example.jwtvalidation.controller;

import com.example.jwtvalidation.security.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/jwt")
public class JwtController {

    private final JwtUtil jwtUtil;

    public JwtController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // Helper endpoint to create a token for testing the validation endpoint.
    @PostMapping("/generate")
    public ResponseEntity<Map<String, Object>> generateToken(
            @RequestBody Map<String, String> request) {

        String username = request.get("username");
        if (username == null || username.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "username is required"));
        }

        String token = jwtUtil.generateToken(username);
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "token", token,
                "message", "Copy this token into the validate endpoint"
        ));
    }

    // Main exam endpoint: validate the signature/expiry and extract claims.
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(
            @RequestBody Map<String, String> request) {

        String token = request.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "token is required"));
        }

        try {
            Claims claims = jwtUtil.validateTokenAndExtractClaims(token);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("status", "Token Valid");
            response.put("username", claims.getSubject());
            response.put("claims", claims);
            return ResponseEntity.ok(response);

        } catch (ExpiredJwtException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "Token Expired"));
        } catch (JwtException | IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "Invalid Token"));
        }
    }
}
