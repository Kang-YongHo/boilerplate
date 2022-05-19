package com.demo.modules.common.advisor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class CommonExceptionAdvisor{

//    @ExceptionHandler
//    public String handleRuntimeException(HttpServletRequest req, RuntimeException e) {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        log.info("Authentication : {}", authentication);
//        Account account = ((UserAccount) authentication.getPrincipal()).getAccount();
//        if (account != null) {
//            log.info("'{}' requested '{}'", account.getName(), req.getRequestURI());
//        } else {
//            log.info("requested '{}'", req.getRequestURI());
//        }
//        log.error("bad request", e);
//        return "error";
//    }
}
