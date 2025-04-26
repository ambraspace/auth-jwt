package com.ambraspace.auth.jwt;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@ConfigurationProperties(prefix = "jwt")
@Getter @Setter @NoArgsConstructor
public class Properties
{

	/**
	 * URL for verification of 2FA code
	 */
	private String verifyUrl = "/verify";

	/**
	 * URL for getting new JWT after the expiration
	 */
	private String refreshUrl = "/refreshtoken";

	/**
	 * Secret key for generation of tokens
	 */
	private String secret;

	/**
	 * Secret key for generation of temporary tokens before 2FA authentication
	 */
	private String secret2FA;

	/**
	 * How long the generated tokens will be valid
	 */
	private Duration tokenValidity = Duration.ofDays(2);

	/**
	 * How long temporary token before 2FA will be valid
	 */
	private Duration tokenValidity2FA = Duration.ofMinutes(2);

	/**
	 * How long after the token expiration a new one can be acquired
	 */
	private Duration refreshTokenValidity = Duration.ofHours(2);

}
