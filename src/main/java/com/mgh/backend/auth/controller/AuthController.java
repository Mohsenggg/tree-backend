package com.mgh.backend.auth.controller;


import com.mgh.backend.auth.domain.dto.AuthRequestDto;
import com.mgh.backend.auth.domain.dto.AuthResponseDto;
import com.mgh.backend.auth.domain.dto.RegisterRequestDto;
import com.mgh.backend.auth.domain.dto.register.*;
import com.mgh.backend.auth.security.SecurityUtils;
import com.mgh.backend.auth.service.AuthService;
import com.mgh.backend.auth.service.RegistrationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:4200", "https://rahem-social.web.app"}) // should be removed and configured with the filter chain

public class AuthController {

    private final RegistrationService registrationService;
    private final AuthService authService;

    public AuthController(RegistrationService registrationService, AuthService authService) {
        this.registrationService = registrationService;
        this.authService = authService;
    }


    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@RequestBody @Valid RegisterRequestDto request){
        AuthResponseDto authenticationResponse = authService.register(request);
        return ResponseEntity.ok(authenticationResponse);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody AuthRequestDto request){
        AuthResponseDto authenticationResponse = authService.login(request);
        return ResponseEntity.ok(authenticationResponse);
    }

    @PostMapping("/invitation/generate")
    public ResponseEntity<InvitationCodeResponseDto> generateInvitation(
            @RequestBody @Valid InvitationCodeGenerateRequestDto request,
            Authentication authentication) {
        long userId = SecurityUtils.requireUserId(authentication);
        InvitationCodeResponseDto response = registrationService.generateInvitationCode(request, userId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/invitation/check")
    public ResponseEntity<RegistrationInitiateResponseDto> initiate(@RequestBody @Valid RegistrationInitiateRequestDto request) {
        RegistrationInitiateResponseDto response = registrationService.initiateRegistration(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register/submit")
    public ResponseEntity<Void> submit(@RequestBody @Valid RegistrationSubmitRequestDto request) {
        registrationService.submitRegistration(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/register/submit/approve")
    public ResponseEntity<String> directApprove(@RequestBody @Valid RegistrationSubmitRequestDto request) {
        String fullName = registrationService.directApprove(request);
        return ResponseEntity.ok("Welcome "+fullName +" Your Account Created Successfully.");
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> approve(@PathVariable("id") Long id, Authentication authentication) {
        String approvedBy = authentication != null ? authentication.getName() : "system";
        String fullName = registrationService.approveRegistration(id, approvedBy);
        return ResponseEntity.ok("Welcome "+fullName +" Your Account Created Successfully.");
    }

    /**
     * Public endpoint – no authentication required.
     * Returns {"available": true} when the username is free, {"available": false} when taken.
     */
    @GetMapping("/check-username")
    public ResponseEntity<Map<String, Boolean>> checkUsername(@RequestParam String username) {
        boolean available = authService.isUsernameAvailable(username);
        return ResponseEntity.ok(Map.of("available", available));
    }

    /**
     * Public endpoint – no authentication required.
     * Returns {"available": true} when the email is not yet registered, {"available": false} when taken.
     * Check is case-insensitive (user@email.com == User@Email.com).
     */
    @GetMapping("/check-email")
    public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestParam String email) {
        boolean available = authService.isEmailAvailable(email);
        return ResponseEntity.ok(Map.of("available", available));
    }

    /**
     * Public endpoint – no authentication required.
     * Returns {"available": true} when the phone number is free, {"available": false} when taken.
     */
    @GetMapping("/check-phone")
    public ResponseEntity<Map<String, Boolean>> checkPhone(@RequestParam String phone) {
        boolean available = authService.isPhoneAvailable(phone);
        return ResponseEntity.ok(Map.of("available", available));
    }
}
