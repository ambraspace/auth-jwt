package com.ambraspace.auth.jwt;

import java.io.Serializable;
import java.time.ZonedDateTime;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter @RequiredArgsConstructor
public class JwtResponse implements Serializable {

    private static final long serialVersionUID = -8091879091924046844L;

    private final String jwttoken;

    private final String username;

    private final ZonedDateTime exp;

}