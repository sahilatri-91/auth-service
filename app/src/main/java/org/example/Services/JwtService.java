package org.example.Services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.Signature;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService
{
// SECRET KEY
    public static final String  SECRET="357638792F423F4428472B4B6250655368566D597133743677397A2443264629";

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }
public<T> T extractClaim(String token, Function<Claims,T> claimResolver){
         Claims claims= extractAllClaims(token);
         return   claimResolver.apply(claims);
}
public Date extractExipration(String token)
{
    return extractClaim(token,Claims::getExpiration);
}
private boolean isTokenExpired(String token){
        return extractExipration(token).before(new Date());
}

public boolean validateToken(String token, UserDetails userDetails){
        final String username=extractUsername(token);
        return (username.equals(userDetails.getUsername())&& isTokenExpired(token));
}
private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
}

private String createToken(Map<String,Object> claims,String username){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()*1000*60*1))
                .signWith(getSignKey(), SignatureAlgorithm.ES256).compact();

}



public Key getSignKey(){
        byte[] keyBytes= Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
}

}
