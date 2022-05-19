package com.demo;

import com.demo.config.security.UserDetailServiceImpl;
import com.demo.config.security.jwt.JwtProvider;
import com.demo.modules.account.domain.Account;
import com.demo.modules.account.domain.UserAccount;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RestController
@RequiredArgsConstructor
public class MainController {

    private final UserDetailServiceImpl userDetailService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @GetMapping("/hello")
    public HttpStatus hello() {
        return HttpStatus.OK;
    }

    @GetMapping("/")
    public void main(HttpServletRequest req, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserAccount) {
            Account account = ((UserAccount) authentication.getPrincipal()).getAccount();
            log.info(String.valueOf(account));
        }
        log.info(String.valueOf(req));
        log.info(String.valueOf(model));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletResponse response, @RequestParam String name, @RequestParam String password) {
        UserDetails principal = userDetailService.loadUserByUsername(name);
        if (!passwordEncoder.matches(password, principal.getPassword()))
            throw new UsernameNotFoundException("invalid Password");

        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);

        String token = jwtProvider.createToken(authentication);
        response.setHeader("Authorization", token);

        Cookie cookie = new Cookie("Authorization", token);
//        CookieUtils.addCookie(response, "Authorization", token, 180);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);

        return ResponseEntity.ok(token);
    }

    @GetMapping("/login/kakao")
    public ResponseEntity kakaoLogin(@RequestParam("code") String code) {
        log.info("code : {}", code);

        RestTemplate restTemplate = new RestTemplateBuilder().build();

        // request header
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // request body
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", "c8914824e8ffa0e7cc907db02bc8ba4b");
        body.add("redirect_uri", "http://localhost:8080/login/kakao");
        body.add("code", code);

        // build the request
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<KakaoLoginResponse> response = restTemplate.postForEntity("https://kauth.kakao.com/oauth/token", entity, KakaoLoginResponse.class);
        if(response.hasBody()) {
            log.info("KakaoLoginResponse : {}", response);
        }

        return response;
    }
}
