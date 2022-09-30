package it.bitrock.ssooauth2jwtdemo.service;

import it.bitrock.ssooauth2jwtdemo.jwt.JwtBuilder;
import it.bitrock.ssooauth2jwtdemo.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class LoginService {
    @Autowired
    AccountRepository accountRepository;

    @Autowired
    OAuth2AuthorizedClientService authorizedClientService;

    public ResponseEntity login(OAuth2AuthenticationToken authentication){
        if (authentication.isAuthenticated()){
            if(accountRepository.existsByUsernameIgnoreCase(authentication.getPrincipal().getAttributes().get("email").toString())){
                return ResponseEntity.ok(JwtBuilder.successfulAuthentication(accountRepository
                        .findByEmail(authentication.getPrincipal().getAttributes().get("email").toString())));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
