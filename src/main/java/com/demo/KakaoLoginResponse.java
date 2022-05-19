package com.demo;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class KakaoLoginResponse {
    String token_type;
    String access_token;
    Long expires_in;
    String refresh_token;
    Long refresh_token_expires_in;
    String scope;
}
