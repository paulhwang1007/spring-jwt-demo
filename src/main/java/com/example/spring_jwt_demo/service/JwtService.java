package com.example.spring_jwt_demo.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Fields and Config
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    // TODO: See Notion for full explanation on what each method does

    // ----------------------------- Signing the Token ---------------------------------------

    // Returns the Signing Key of Secret Key
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // ----------------------------- Extracting Data from Tokens -----------------------------

    // Returns the full payload after verifying the signing key
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Allows you to extract the value of a specific claim from the full payload
    // Done through extractUsername and extractExpiration
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Returns the value of "sub" from token's payload
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Returns the value of "exp" from token's payload
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // ----------------------------- Token Validation -----------------------------------------

    // Checks if the token belongs to userDetails and is not expired
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // Checks if the token is expired or not
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // ----------------------------- Token Creation -------------------------------------------

    // Version to use if you don't want to add any custom data
    // Passes an empty map along with the existing userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // Version to use if you want to add custom data
    // If not, then extraClaims is just an empty map from the former version
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    // Creates the JWT token
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder() // starts the JWT builder
                .setClaims(extraClaims) // adds the custom fields
                .setSubject(userDetails.getUsername()) // sets "sub" to username
                .setIssuedAt(new Date(System.currentTimeMillis())) // sets "iat" to current time
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // sets "exp" to current time + expiration
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // signs the token with the signing key
                .compact(); // serializes into JWT string with <Header>.<Payload>.<Signature> format
    }

    // Returns the value of jwtExpiration: How long it takes to expire
    public long getExpirationTime() {
        return jwtExpiration;
    }
}