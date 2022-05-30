package com.demo.modules.account.web;

import com.demo.config.security.UserDetailServiceImpl;
import com.demo.modules.account.application.AccountService;
import com.demo.modules.account.domain.Account;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

@RequiredArgsConstructor
public class WithAccountSecurityContextFactory implements WithSecurityContextFactory<WithAccount> {

    private final AccountService accountService;

    private final UserDetailServiceImpl userDetailService;

    @Override
    public SecurityContext createSecurityContext(WithAccount annotation) {
        String name = annotation.value();
        Account account = new Account();
        account.setName(name);
        account.setEmail(name + "@test.com");
        account.setPassword("test");
        accountService.create(account);

        UserDetails userDetails = userDetailService.loadUserByUsername(account.getName());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            userDetails, userDetails.getPassword(), userDetails.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
