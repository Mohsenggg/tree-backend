package com.mgh.backend.auth.service;

import com.mgh.backend.auth.domain.dto.*;
import com.mgh.backend.auth.domain.entity.UserAuth;
import com.mgh.backend.auth.domain.entity.UserProfile;
import com.mgh.backend.auth.domain.enums.Role;
import com.mgh.backend.auth.repository.UserAuthRepo;
import com.mgh.backend.auth.repository.UserProfileRepository;
import com.mgh.backend.auth.security.service.JwtService;
import com.mgh.backend.auth.security.adapter.UserAuthAdapter;
import com.mgh.backend.tree.domain.entity.Node;
import com.mgh.backend.tree.domain.enums.TreeNodeStatus;
import com.mgh.backend.tree.repository.NodeRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserAuthRepo userAuthRepo;
    private final NodeRepo nodeRepo;
    private final RegistrationService registrationService;
    private final UserProfileRepository userProfileRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Transactional
    public AuthResponseDto register(RegisterRequestDto dto) {
        // ── 1. Resolve the node linked to this invitation code ──────────────
        Node node = null;
        String fullName = dto.getFullName();

        if (dto.getInvitationCode() != null && !dto.getInvitationCode().isBlank()) {
            Long nodeId = registrationService.validateAndExtractNodeId(dto.getInvitationCode());
            node = nodeRepo.findByNodeIdAndIsDeletedFalse(nodeId)
                    .orElseThrow(() -> new IllegalArgumentException("Node not found for this invitation code"));

            // Validate invitation code matches the node's stored code
            if (!dto.getInvitationCode().equals(node.getInvitationCode())) {
                throw new IllegalArgumentException("Invitation code does not match");
            }

            // ── 2. Guard: only INACTIVE nodes can register ──────────────────
            if (node.getStatus() == TreeNodeStatus.ACTIVATED) {
                throw new IllegalStateException("This invitation has already been used. Please log in instead.");
            }
            if (node.getStatus() == TreeNodeStatus.PENDING) {
                throw new IllegalStateException("A registration for this invitation is pending approval.");
            }
            if (node.getStatus() == TreeNodeStatus.LOCKED) {
                throw new IllegalStateException("This invitation is locked. Please contact the administrator.");
            }

            // Derive fullName from node if caller didn't supply one
            if (fullName == null || fullName.isBlank()) {
                String parentName = "";
                if (node.getFatherId() != null) {
                    parentName = nodeRepo.findByNodeIdAndIsDeletedFalse(node.getFatherId())
                            .map(Node::getNodeName).orElse("");
                } else if (node.getMotherId() != null) {
                    parentName = nodeRepo.findByNodeIdAndIsDeletedFalse(node.getMotherId())
                            .map(Node::getNodeName).orElse("");
                }
                fullName = (node.getNodeName() + (parentName.isBlank() ? "" : " " + parentName)).trim();
            }
        }

        if (fullName == null || fullName.isBlank()) {
            fullName = dto.getUsername();
        }

        // ── 3. Guard: enforce uniqueness for username and email ──────────────
        if (userAuthRepo.existsByUsernameIgnoreCase(dto.getUsername())) {
            throw new IllegalArgumentException("Username is already taken.");
        }
        if (userAuthRepo.existsByEmailIgnoreCase(dto.getEmail())) {
            throw new IllegalArgumentException("Email is already registered.");
        }
        if (dto.getPhone() != null && !dto.getPhone().isBlank() &&
                userAuthRepo.existsByPhone(dto.getPhone().trim())) {
            throw new IllegalArgumentException("Phone number is already registered.");
        }

        // ── 4. Create UserAuth ───────────────────────────────────────────────
        UserAuth userAuth = UserAuth.builder()
                .username(dto.getUsername())
                .email(dto.getEmail())
                .fullName(fullName)
                .phone(dto.getPhone())
                .password(passwordEncoder.encode(dto.getPassword()))
                .enabled(true)
                .locked(false)
                .role(Role.USER)
                .build();

        userAuth = userAuthRepo.save(userAuth);

        // ── 5. Create UserProfile (birthDate / gender / address) ─────────────
        if (dto.getBirthDate() != null || dto.getGender() != null || dto.getAddress() != null) {
            UserProfile profile = UserProfile.builder()
                    .userAuth(userAuth)
                    .birthDate(dto.getBirthDate())
                    .gender(dto.getGender())
                    .address(dto.getAddress())
                    .build();
            userProfileRepository.save(profile);
        }

        // ── 6. Activate the node ─────────────────────────────────────────────
        if (node != null) {
            node.setUserId(userAuth.getId());
            node.setStatus(TreeNodeStatus.ACTIVATED);
            nodeRepo.save(node);
        }

        // ── 7. Issue JWT ─────────────────────────────────────────────────────
        UserAuthAdapter userAuthAdapter = new UserAuthAdapter(userAuth);
        TokenExpiryDto tokenWithExpiry = jwtService.generateToken(userAuthAdapter);

        return AuthResponseDto.builder()
                .token(tokenWithExpiry.getToken())
                .user(userToUserDto(userAuth))
                .expiresIn(tokenWithExpiry.getExpiry())
                .build();
    }

    // ===================================================================
    // ===================================================================

    private Authentication getAuthentication(AuthRequestDto request) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
    }

    public AuthResponseDto login(AuthRequestDto request) {

        // 1️⃣ Authenticate (delegates to AuthenticationManager, throws AuthenticationException on bad credentials/status)
        Authentication authentication = getAuthentication(request);

        // 2️⃣ Authentication succeeded → get principal
        UserAuthAdapter userAuthAdapter = (UserAuthAdapter) authentication.getPrincipal();
        UserAuth userAuth = userAuthAdapter.getUserAuth();

        // 3️⃣ Generate JWT
        TokenExpiryDto tokenWithExpiry = jwtService.generateToken(userAuthAdapter);

        return AuthResponseDto.builder()
                .token(tokenWithExpiry.getToken())
                .user(userToUserDto(userAuth))
                .expiresIn(tokenWithExpiry.getExpiry())
                .build();
    }

    // ===================================================================
    // ===================================================================

    private UserDataDto userToUserDto(UserAuth userAuth) {
        String nodeName = null;
        if (userAuth.getId() != null) {
            nodeName = nodeRepo.findFirstByUserIdAndIsDeletedFalse(userAuth.getId())
                    .map(Node::getNodeName)
                    .orElse(null);
        }
        if (nodeName == null || nodeName.isBlank()) {
            nodeName = userAuth.getFullName();
        }
        if (nodeName == null || nodeName.isBlank()) {
            nodeName = userAuth.getUsername();
        }

        String fullName = userAuth.getFullName();
        if (fullName == null || fullName.isBlank()) {
            fullName = nodeName;
        }

        return UserDataDto.builder()
                .id(userAuth.getId())
                .username(userAuth.getUsername())
                .email(userAuth.getEmail())
                .fullName(fullName)
                .nodeName(nodeName)
                .roles(Collections.singleton(userAuth.getRole()))
                .build();
    }

    /**
     * Returns true when the username is not yet taken (case-insensitive).
     * Used by the registration form for real-time availability feedback.
     */
    public boolean isUsernameAvailable(String username) {
        if (username == null || username.isBlank()) return false;
        return !userAuthRepo.existsByUsernameIgnoreCase(username.trim());
    }

    /**
     * Returns true when the email is not yet registered (case-insensitive).
     * Used by the registration form for real-time availability feedback.
     */
    public boolean isEmailAvailable(String email) {
        if (email == null || email.isBlank()) return false;
        return !userAuthRepo.existsByEmailIgnoreCase(email.trim());
    }

    /**
     * Returns true when the phone number is not yet registered.
     * Used by the registration form for real-time availability feedback.
     */
    public boolean isPhoneAvailable(String phone) {
        if (phone == null || phone.isBlank()) return false;
        return !userAuthRepo.existsByPhone(phone.trim());
    }

}
