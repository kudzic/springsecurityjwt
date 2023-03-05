package com.example.security2.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    //You can generate this online
    private  static final String SECRET_KEY="566D5970337336763979244226452948404D635166546A576E5A723474377721";

    //For us to be able to extract information from the token like username and also to validate the token
    // basically if  we want to work with the token we have to install a JJWT dependency in our pom.xml file
    public String extractUsername(String jwtToken) {

        return extractClaim(jwtToken,Claims::getSubject);

    }

    public <T> T extractClaim(String jwtToken, Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaims(jwtToken);
        //This will extract a single claim from the claims in the header body
        return claimsResolver.apply(claims);
    }


    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    //Will create token which includes extraClaims
    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis()+1000 * 60 * 24 ))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
    }

    public boolean isTokenValid(String jwtToken,UserDetails userDetails){
        final String username=extractUsername(jwtToken);
        return (username.equals(userDetails.getUsername()) && ! isTokenExpired(jwtToken));
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken,Claims::getExpiration);
    }

    //This method is going to be responsible to getting all the claims in header
    public Claims extractAllClaims(String jwtToken){
        //Jwts is from the dependencies that we added
        return Jwts
                .parserBuilder()
                //This is the key used to verify any Jwt issued by the authorization server
                //It is used in conjuction with the signing algortithm to make sure that their secure
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();

    }

    //This will decode the secret key bytes
    private Key getSignInKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        //This will use the algorithm to decode the key
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
