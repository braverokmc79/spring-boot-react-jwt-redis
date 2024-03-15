package com.shop.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "/error")
@Log4j2
public class CustomErrorController implements ErrorController {
    private final String VIEW_PATH = "errors/";


    @GetMapping
    public String handleError(HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        Object message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);

        if(status != null){
            int statusCode = Integer.valueOf(status.toString());
            log.warn(">>>>>>>>> statusCode  ===> 에러 코더:{}, 에러 메시지:{} ",status,message);

            if(statusCode == HttpStatus.NOT_FOUND.value() || statusCode==HttpStatus.UNAUTHORIZED.value()){
                return VIEW_PATH + "404";
            }
            if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()){
                return VIEW_PATH + "500";
            }
        }
        return VIEW_PATH +"error";
    }

    @GetMapping(value = "404")
    public String page404(HttpServletRequest request) {
        return VIEW_PATH + "404";
    }

    @GetMapping(value = "500")
    public String page500(HttpServletRequest request) {
        return VIEW_PATH + "500";
    }



}


