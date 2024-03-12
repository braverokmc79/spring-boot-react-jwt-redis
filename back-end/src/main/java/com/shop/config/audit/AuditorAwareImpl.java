package com.shop.config.audit;

import com.shop.config.auth.PrincipalDetails;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuditorAwareImpl implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String userId = "";
        if(authentication != null){
            //userId = authentication.getName();
            try{
                PrincipalDetails principal= (PrincipalDetails) authentication.getPrincipal();
                userId = principal.getEmail();
            }catch (Exception e){
                userId = "anonymous";
            }

        }
        return Optional.of(userId);
    }

}