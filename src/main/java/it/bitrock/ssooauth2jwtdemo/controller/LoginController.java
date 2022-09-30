package it.bitrock.ssooauth2jwtdemo.controller;

import it.bitrock.ssooauth2jwtdemo.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

        @Autowired
        private LoginService loginService;


        @GetMapping("/loginSuccess")
        public ResponseEntity<String> login(OAuth2AuthenticationToken authentication) {
                return loginService.login(authentication);
        }
}
