package com.codesphere.api_gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpStatus;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;


@Component
public class TokenFilter extends AbstractGatewayFilterFactory<TokenFilter.Config> {

    private static final String SECRET = "wzJLAFcoVPLFzXXODak5peXzhM9rDypG6b/xw0YqOXEXOezjwQhEgQUIloiiMDQataIAY72QbpiLi2XWw8VlJA==";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    public TokenFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getPath().toString();

            if (path.endsWith("/api/v1/user/login") || path.endsWith("/api/v1/user/register")) {
                return chain.filter(exchange
                        .mutate()
                        .request(r -> r.header("X-Secret-Key", "SECRET"))
                        .build());
            }

            HttpHeaders header = exchange.getRequest().getHeaders();

            if (!header.containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new RuntimeException("Authorization header is missing!");
            }

            String authHeader = header.getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                throw new RuntimeException("Authorization header is invalid!");
            }

            String token = authHeader.substring(7);

            try {
                Claims claims = Jwts.parser()
                        .verifyWith(SECRET_KEY)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();
                exchange = exchange
                        .mutate()
                        .request(r -> r.header("X-Secret-Key", "SECRET"))
                        .build();
            } catch (Exception e) {
                throw new RuntimeException("Token is invalid");
            }
            return chain.filter(exchange);
        };
    }

    public static class Config {
        // Configuration properties if needed
    }
}