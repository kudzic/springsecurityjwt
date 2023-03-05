package com.example.security2.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
//The reason why we extend to OncePerRequestFilter is the make sure that our
// Jwt Filter is run every single time a request has been made to our server
//The Component ,Repository and Service annotations can be used in this class as they do the same thing
@Component
@RequiredArgsConstructor
public class JwtAthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private final JwtService jwtService;
    @Autowired
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
                                    //This is our request
                                     @NonNull HttpServletRequest request,
                                    //This is our response
                                    @NonNull HttpServletResponse response,
                                    //Filter Chain provide the list of other filterchains we need to execute
                                    @NonNull      FilterChain filterChain) throws ServletException, IOException {

        //The reason why we create this authHeader to get our Header information
        // ,because when we make a call we need to pass the jwt authentication token within the header called Authorization
        final String authHeader=request.getHeader("Authorization");
        final String jwtToken;
        final String userEmail;

        //Implement the check jwtToken
        if(authHeader == null || !authHeader.startsWith("Bearer ") ){
            //This will pass on the http request to another filter in the chain since it did not meet the filter's requirements
            filterChain.doFilter(request,response);
            return;
        }
        //To get the jwtToken we have to use the header and take the substring starting from 7
        // since the all the Header String starts with Bearer and a whitespace
        jwtToken=authHeader.substring(7);

        //We need to create a service class that will be responsible for extracting the email from the jwtToken
        userEmail=jwtService.extractUsername(jwtToken);
        //We have to check if the user is not authenticated by using the SecurityContextHolder which will give us the authentication
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() ==null){
            //We then need to check if the user is in the database
            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwtToken,userDetails)){
                //This UserPasswordAuthenticationToken is required by SecurityContext the to update the jwt token
                UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                //This step is done to add more details to our token
                authToken.setDetails(
                        //This will add the request information into our token
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //Now that we are done with the token we need to update the SecurityContext so that it can be authenticated

                //This is how you update the securitycontext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        //We always have to add this to make sure that the filter will move on to the next filter on the chain
        // so that all the filters are executed
        filterChain.doFilter(request,response);

    }
}
