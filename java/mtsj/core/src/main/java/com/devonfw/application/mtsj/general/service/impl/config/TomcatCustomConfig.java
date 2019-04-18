package com.devonfw.application.mtsj.general.service.impl.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

import javax.inject.Inject;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import com.devonfw.module.security.jwt.config.KeyStoreConfigProperties;

@Configuration
public class TomcatCustomConfig {

	@Inject
	private KeyStore keyStore;

	@Inject
	private KeyStoreConfigProperties keyStoreConfigProperties;


	@Bean
	public ServletWebServerFactory servletContainer() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, Exception {
		TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
	//	tomcat.addAdditionalTomcatConnectors(createSslConnector());
		//		tomcat.getSslStoreProvider().getKeyStore().load(new FileInputStream(new File(keyStoreConfigProperties.getKeyStoreLocation())), keyStoreConfigProperties.getPassword().toCharArray());
		tomcat.addAdditionalTomcatConnectors(httpConnector());
		return tomcat;
	}

//	private Connector createSslConnector() {
//		Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
//		Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
//		//connector.setScheme("http");
//		connector.setPort(8080);
//		connector.setSecure(true);
//		connector.setRedirectPort(8443);
//		protocol.setSSLEnabled(true);
//		protocol.setKeystoreFile(keyStoreConfigProperties.getKeyStoreLocation());
//		protocol.setKeystorePass(keyStoreConfigProperties.getPassword());
////	protocol.setTruststoreFile(truststore.getAbsolutePath());
////	protocol.setTruststorePass("123456");
//		protocol.setKeyAlias(keyStoreConfigProperties.getKeyAlias());
//		return connector;
//	}

	private Connector httpConnector() {
		Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
	//	Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
//		connector.setScheme("http");
//		connector.setSecure(false);
	//	connector.setScheme("https");
		connector.setPort(8080);
		//protocol.setKeystoreFile(keyStoreConfigProperties.getKeyStoreLocation());
		connector.setRedirectPort(8443);
//		protocol.setKeystorePass(keyStoreConfigProperties.getKeyPassword());
//		protocol.setKeystoreType(keyStoreConfigProperties.getKeystoreType());
//		protocol.setSSLEnabled(true);
		return connector;
	}
}
