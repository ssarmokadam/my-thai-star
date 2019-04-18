package com.devonfw.application.mtsj.general.common.base;

import java.security.KeyStoreException;
import java.security.Signer;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64Encoder;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

import com.devonfw.application.mtsj.general.common.api.datatype.Role;
import com.devonfw.application.mtsj.general.common.api.to.UserDetailsClientTo;
import com.devonfw.module.security.jwt.config.JwtTokenConfigProperties;
import com.devonfw.module.security.jwt.config.KeyStoreAccess;
import com.devonfw.module.security.jwt.util.TokenCreator;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Service class for JWT token managing
 *
 */
public class TokenAuthenticationService {

	@Inject
	private static JwtTokenConfigProperties jwtTokenConfigProperties;

	/** Logger instance. */
	private static final Logger LOG = LoggerFactory.getLogger(TokenAuthenticationService.class);

	static final String ISSUER = "MyThaiStarApp";

	static final Integer EXPIRATION_HOURS = 1;

	// static final String SECRET = "ThisIsASecret";

	static final String TOKEN_PREFIX = "Bearer";

	static final String HEADER_STRING = "Authorization";

	static final String EXPOSE_HEADERS = "Access-Control-Expose-Headers";

	static final String CLAIM_SUBJECT = "sub";

	static final String CLAIM_ISSUER = "iss";

	static final String CLAIM_EXPIRATION = "exp";

	static final String CLAIM_CREATED = "iat";

	static final String CLAIM_SCOPE = "scope";

	static final String CLAIM_ROLES = "roles";

	/**
	 * This method returns the token once the Authentication has been successful
	 *
	 * @param res            the {@HttpServletResponse}
	 * @param auth           the {@Authentication} object with the user credentials
	 * @param keyStoreAccess
	 *
	 */
	static void addAuthentication(HttpServletResponse res, Authentication auth, KeyStoreAccess keyStoreAccess) {

		List<String> scopes = new ArrayList<>();
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		for (GrantedAuthority authority : authorities) {
			scopes.add(authority.getAuthority());
		}
		Map<String, Object> claims = new HashMap<>();
		claims.put(CLAIM_ISSUER, ISSUER);
		claims.put(CLAIM_SUBJECT, auth.getName());
		claims.put(CLAIM_SCOPE, scopes);
		claims.put(CLAIM_ROLES, scopes);
		claims.put(CLAIM_CREATED, generateCreationDate() / 1000);
		claims.put(CLAIM_EXPIRATION, generateExpirationDate() / 1000);
		JSONObject obj = new JSONObject(claims);
		try {
			System.out.println(keyStoreAccess.getKeyStore().isKeyEntry("testuser"));
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("RSAPrivateKey========================== "
				+ ((RSAPrivateKey) keyStoreAccess.getPrivateKey("testuser", "changeit")).getModulus().toString());
		RsaSigner rsaSigner = new RsaSigner((RSAPrivateKey) keyStoreAccess.getPrivateKey("testuser", "changeit"));
		Map<String, String> headers = new HashMap<>();
		headers.put("alg", "RS256");
		headers.put("typ", "JWT");
		TokenCreator tokenCreator = new TokenCreator(claims.toString(), rsaSigner, headers);

		// Jwt token = JwtHelper.encode(obj.toString(), rsaSigner, headers);
//		Base64Encoder encoder=new Base64Encoder();
//		encoder.
		// headers.put("alg", );

		Jwt token = tokenCreator.generateToken(obj.toString(), rsaSigner, headers);// generateToken(auth);
		System.out.println("token " + token.toString());
		System.out.println("Token generated :: " + token.getClaims());
		res.addHeader(EXPOSE_HEADERS, HEADER_STRING);
		res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + token.getEncoded());
	}

	/**
	 * This method validates the token and returns a
	 * {@link UsernamePasswordAuthenticationToken}
	 *
	 * @param request the {@link HttpServletRequest}
	 * @return the {@link UsernamePasswordAuthenticationToken}
	 */
//	static Authentication getAuthentication(HttpServletRequest request) {
//
//		String token = request.getHeader(HEADER_STRING);
//		if (token != null) {
//
//			// The JWT parser will throw an exception if the token is not well formed or the
//			// token has expired
//			String user = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token.replace(TOKEN_PREFIX, "")).getBody()
//					.getSubject();
//			return user != null ? new UsernamePasswordAuthenticationToken(user, null, getAuthorities(token)) : null;
//
//		}
//
//		return null;
//	}

	static Collection<? extends GrantedAuthority> getAuthorities(String token) {

		List<String> roles = getRolesFromToken(token);
		List<GrantedAuthority> authorities = new ArrayList<>();
		for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority(role));
		}
		return authorities;

	}

//  static String generateToken(Authentication auth) {
//
//    List<String> scopes = new ArrayList<>();
//    Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
//    for (GrantedAuthority authority : authorities) {
//      scopes.add(authority.getAuthority());
//    }
//
//    Map<String, Object> claims = new HashMap<>();
//    claims.put(CLAIM_ISSUER, ISSUER);
//    claims.put(CLAIM_SUBJECT, auth.getName());
//    claims.put(CLAIM_SCOPE, scopes);
//    claims.put(CLAIM_ROLES, scopes);
//    claims.put(CLAIM_CREATED, generateCreationDate() / 1000);
//    claims.put(CLAIM_EXPIRATION, generateExpirationDate() / 1000);
//    LOG.info(claims.toString());
//    return Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS512, SECRET).compact();
//  }

	static Long generateCreationDate() {

		return new Date().getTime();
	}

	static Long generateExpirationDate() {

		int expirationTerm = (60 * 60 * 1000) * EXPIRATION_HOURS;
		return new Date(new Date().getTime() + expirationTerm).getTime();
	}

	/**
	 * Extracts and returns the {@link UserDetailsClientTo} from the JWT token
	 *
	 * @param token the JWT token
	 * @return the {@link UserDetailsClientTo} object
	 */
	public static UserDetailsClientTo getUserdetailsFromToken(String token) {
		UserDetailsClientTo userDetails = new UserDetailsClientTo();
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			userDetails.setName(auth.getName());
		}

		return userDetails;
	}

	static List<String> getRolesFromToken(String token) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String[] roleArray = null;
		auth.getAuthorities().toArray(roleArray);

		return Arrays.asList(roleArray);
	}

	private static String getAlgorithm() {
		return jwtTokenConfigProperties.getPropsAsMap().get("alg");
	}

}
