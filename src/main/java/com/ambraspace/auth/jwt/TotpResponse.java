package com.ambraspace.auth.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter @RequiredArgsConstructor
public class TotpResponse {

    private final String username;

    private final String jwttoken;

    private boolean using2FA = true;

}
