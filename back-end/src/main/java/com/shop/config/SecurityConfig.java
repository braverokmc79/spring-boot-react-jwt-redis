package com.shop.config;

import com.querydsl.jpa.impl.JPAQueryFactory;
import com.shop.exception.CustomAuthenticationEntryPoint;
import com.shop.config.filter.JwtAuthenticationFilter;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//@EnableGlobalMethodSecurity(prePostEnabled = true)//기본값 true 업데이트 됩
public class SecurityConfig  {


    private  final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public JPAQueryFactory queryFactory(EntityManager em){
        return new JPAQueryFactory(em);
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //JWT 를 사용하면  csrf 보안이 설정 필요없다. 그러나 여기 프로젝트에서는 세션방식과 jwt 방식을 둘다적용 중이라 특정 페이지만 제외 처리
        http.csrf(c -> {
            c.ignoringRequestMatchers("/admin/**","/api/**", "/oauth2/**" ,"/error/**");
        });

        //http.headers((headers) -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));


        //이 프로젝트는  세션 + JWT 를 사용하지 때문에 주석
        //http.sessionManagement(sessionManagementConfigurer ->sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        //세션방식의  form 로그인 처리
        http.formLogin(login-> login
                        .loginPage("/members/login")
                        .defaultSuccessUrl("/", true)
                        .usernameParameter("email")
                        .failureUrl("/members/login/error"))
                .logout(logoutConfig ->logoutConfig.logoutRequestMatcher(new AntPathRequestMatcher("/members/logout")).logoutSuccessUrl("/"))
                .exceptionHandling(exceptionConfig-> exceptionConfig.authenticationEntryPoint(new Http403ForbiddenEntryPoint()));


        http.authorizeHttpRequests(request->request
                .requestMatchers("/css/**", "/js/**", "/img/**","/images/**").permitAll()
                .requestMatchers("/", "/members/**", "/item/**", "/main/**", "/error/**" ).permitAll()

                 //JWT 일반 접속 설정
                .requestMatchers("/api/todo/**").permitAll()
                .requestMatchers(  "/api/auth/signup","/api/auth/signin" , "/api/auth/reissue", "/api/auth/logout").permitAll()
                //JWT 관리자 페이지 설정
                .requestMatchers( "/api/admin/**").hasAuthority("ADMIN")


                //세션방식  --> 관리자 페이지는 설정
                .requestMatchers("/admin/**").hasAuthority("ADMIN")
                .anyRequest().authenticated()
        );
        //.exceptionHandling(exceptionConfig->exceptionConfig.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));



         //=======api 페이지만  JWT  필터 설정(jwtAuthenticationFilter 에서 shouldNotFilter 메서드로 세션 페이지는 필터를 제외 시켰다.)
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        //에외 처리
        .exceptionHandling(exceptionConfig->exceptionConfig.authenticationEntryPoint(new CustomAuthenticationEntryPoint()) );

       return http.build();
    }




}
