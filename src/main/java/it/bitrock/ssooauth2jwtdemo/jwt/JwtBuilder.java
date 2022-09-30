package it.bitrock.ssooauth2jwtdemo.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import it.bitrock.ssooauth2jwtdemo.model.Account;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.time.LocalDate;


public class JwtBuilder {


    public static String successfulAuthentication(Account account)  {
        Algorithm algorithm= Algorithm.HMAC256("secret".getBytes());
        String access_token = JWT.create()
                .withSubject(account.getName())
                .withExpiresAt(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
                .withClaim("roles",account.getRole().getName())
                .sign(algorithm);
        return "Bitrock "+ access_token;
    }
}
