package com.devonfw.application.mtsj.general.service.impl.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.servlet.Filter;

import org.apache.catalina.filters.SetCharacterEncodingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.filter.CharacterEncodingFilter;

import com.devonfw.module.logging.common.api.DiagnosticContextFacade;
import com.devonfw.module.logging.common.impl.DiagnosticContextFacadeImpl;
import com.devonfw.module.logging.common.impl.DiagnosticContextFilter;
import com.devonfw.module.logging.common.impl.PerformanceLogFilter;
import com.devonfw.module.security.jwt.config.JwtTokenConfigProperties;
import com.devonfw.module.security.jwt.config.KeyStoreAccessImpl;
import com.devonfw.module.security.jwt.config.KeyStoreConfigProperties;
import com.devonfw.module.service.common.api.constants.ServiceConstants;

/**
 * Registers a number of filters for web requests.
 *
 */
@Configuration
public class WebConfig {

  private @Autowired AutowireCapableBeanFactory beanFactory;

  /**
   * Register PerformanceLogFilter to log running time of requests.
   *
   * @return filter
   */
  @Bean
  public FilterRegistrationBean performanceLogFilter() {

    FilterRegistrationBean registration = new FilterRegistrationBean();
    Filter performanceLogFilter = new PerformanceLogFilter();
    this.beanFactory.autowireBean(performanceLogFilter);
    registration.setFilter(performanceLogFilter);
    registration.addUrlPatterns("/*");
    return registration;
  }

  /**
   * Bean definition for DiagnosticContextFacade.
   *
   * @return DiagnosticContextFacade
   */
  @Bean(name = "DiagnosticContextFacade")
  public DiagnosticContextFacade diagnosticContextFacade() {

    return new DiagnosticContextFacadeImpl();
  }

  /**
   * Register DiagnosticContextFilter to log service calls with correlation id.
   *
   * @return filter
   */
  @Bean
  public FilterRegistrationBean diagnosticContextFilter() {

    FilterRegistrationBean registration = new FilterRegistrationBean();
    Filter diagnosticContextFilter = new DiagnosticContextFilter();
    this.beanFactory.autowireBean(diagnosticContextFilter);
    registration.setFilter(diagnosticContextFilter);
    registration.addUrlPatterns(ServiceConstants.URL_PATH_SERVICES + "/*");
    return registration;
  }

  /**
   * Register SetCharacterEncodingFilter to convert specical characters correctly.
   *
   * @return filter
   */
  @Bean
  public FilterRegistrationBean setCharacterEncodingFilter() {

    FilterRegistrationBean registration = new FilterRegistrationBean();
    CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
    characterEncodingFilter.setEncoding("UTF-8");
    characterEncodingFilter.setForceEncoding(false);
    this.beanFactory.autowireBean(characterEncodingFilter);
    registration.setFilter(characterEncodingFilter);
    registration.addUrlPatterns("/*");
    return registration;
  }

	@Bean
	public JwtTokenConfigProperties jwtTokenConfigProperties() {
		return new JwtTokenConfigProperties();

	}

	@Bean
	public KeyStoreConfigProperties keyStoreConfigProperties() {
		return new KeyStoreConfigProperties();
	}

	@Bean
	@DependsOn("keyStoreConfigProperties")
	public KeyStore keyStore() {
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance(keyStoreConfigProperties().getKeystoreType());

			Resource keyStoreLocation = new FileSystemResource(
					new File(keyStoreConfigProperties().getKeyStoreLocation()));
			try (InputStream in = keyStoreLocation.getInputStream()) {

				keyStore.load(in, keyStoreConfigProperties().getPassword().toCharArray()); // "changeit".toCharArray()

				System.out.println("Keystore aliases " + keyStore.aliases().nextElement().toString());
			} catch (IOException | NoSuchAlgorithmException | CertificateException e) {

				e.printStackTrace();
			}
		} catch (KeyStoreException e) {

			e.printStackTrace();
		}
		return keyStore;

	}

	@Bean
	@Qualifier("keyStoreAccess")
	public KeyStoreAccessImpl keyStoreAccess() {
		return new KeyStoreAccessImpl();

	}
}