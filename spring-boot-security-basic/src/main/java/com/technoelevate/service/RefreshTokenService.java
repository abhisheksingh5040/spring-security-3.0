package com.technoelevate.service;

import com.technoelevate.config.UserInfoUserDetailsService;
import com.technoelevate.dto.JwtResponse;
import com.technoelevate.dto.RefreshTokenRequest;
import com.technoelevate.entity.RefreshToken;
import com.technoelevate.repository.RefreshTokenRepository;
import com.technoelevate.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    private UserInfoRepository userInfoRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private JwtService jwtService;

    public RefreshToken createRefreshToken(String userName) {
        RefreshToken refreshToken = RefreshToken.builder()
                .userInfo(userInfoRepository.findByName(userName).get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(600000))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    public JwtResponse refreshToken(RefreshTokenRequest request) {
        return checkRefreshToken(request.getRefreshToken())
                .map(this::validateRefreshToken)
                .map(RefreshToken::getUserInfo)
                .map(userInfo -> {
                    String accessToken = jwtService.generateToken(userInfo.getName());
                    return JwtResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(request.getRefreshToken())
                            .build();
                }).orElseThrow(()->new RuntimeException("Refresh token is not present in DB"));
    }

    private Optional<RefreshToken> checkRefreshToken(String token){
        return refreshTokenRepository.findByToken(token);
    }

    private RefreshToken validateRefreshToken(RefreshToken refreshToken){
        if(refreshToken.getExpiryDate().compareTo(Instant.now())<0){
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token expired!!!!");
        }
        return refreshToken;
    }
}
