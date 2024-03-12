package com.shop.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.metrics.MetricsProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Controller
public class WebMvcConfig  implements WebMvcConfigurer {

    private final long MAX_AGE_SECS=3600;  //1시간


    @Value("${uploadPath}")
    String uploadPath;


    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/images/**").addResourceLocations(uploadPath);
    }



    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/todo/**")
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)  // 'Access-Control-Allow-Credentials' header 는 요청 시 자격 증명이 필요함
                .maxAge(MAX_AGE_SECS)
                .allowedOrigins(
                        "http://localhost:5500/"
                        ,"http://127.0.0.1/",
                        "http://localhost:3000/"
                ).exposedHeaders("authorization");  //authorization 헤더를 넘기 위해 exposedHeaders 조건을 추가

        registry.addMapping("/api/**")
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)  // 'Access-Control-Allow-Credentials' header 는 요청 시 자격 증명이 필요함
                .maxAge(MAX_AGE_SECS)
                .allowedOrigins(
                        "http://localhost:5500/"
                        ,"http://127.0.0.1/",
                        "http://localhost:3000/"
                ).exposedHeaders("authorization");  //authorization 헤더를 넘기 위해 exposedHeaders 조건을 추가

    }



}
