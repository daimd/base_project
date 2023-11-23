package com.fwa.ec.learn.base_project.configuration;

import com.fwa.ec.learn.base_project.service.SystemUserDetailsService;
import com.fwa.ec.learn.base_project.utils.RsaKeyProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
@EnableMethodSecurity
public class OauthSecurityConfig {

    private final RsaKeyProperties rsaKeyProperties;
    private SystemUserDetailsService userDetailsService;

    public OauthSecurityConfig(SystemUserDetailsService userDetailsService, RsaKeyProperties rsaKeyProperties) {
        this.userDetailsService = userDetailsService;
        this.rsaKeyProperties = rsaKeyProperties;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration, UserDetailsService userDetailsService) throws Exception {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(bcryptPasswordEncoder());
        authenticationConfiguration.getAuthenticationManager();
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors((cors) -> cors
                        .configurationSource(myWebsiteConfigurationSource())
                )

                .csrf(AbstractHttpConfigurer::disable)
//                .csrf((csrf) -> csrf
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
//                )
//                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//                .securityMatcher(new AntPathRequestMatcher("/api/v1/**"))
                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
                                .anyRequest().authenticated()
                )
//                turn session management office means we must have crsf enabled
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(decoder())))
                .userDetailsService(userDetailsService)
                .exceptionHandling(
                        (ex) -> ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));

        return http.build();
    }

    /*
     * This will allow the /token endpoint to use basic auth and everything else uses the SFC above
     */
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    SecurityFilterChain tokenSecurityFilterChain(HttpSecurity http) throws Exception {
        http

                .cors((cors) -> cors
                        .configurationSource(apiConfigurationSource())
                )
                .csrf(csrfConfigurer -> csrfConfigurer.disable())
                .securityMatcher(new AntPathRequestMatcher("/token"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(decoder())))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                    ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                })
                .userDetailsService(userDetailsService);

        return http.build();
    }

    @Bean
    public PasswordEncoder bcryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //When using jwt(Customizer),
//supply a JwtDecoder instance via OAuth2ResourceServerConfigurer.JwtConfigurer.decoder, or
//expose a JwtDecoder bean
///JWT has 3 parts, the header, payload, and signature.
// The signature is created using by encrypting the header + payload and a secret (or private key).
//    We will do this using asymmetric keys (the private key of a private-public pair) method

    @Bean
    public JwtDecoder decoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeyProperties.rsaPublicKey()).build();
    }

    @Bean
    public JwtEncoder encoder() {
        JWK jwk = new RSAKey.Builder(rsaKeyProperties.rsaPublicKey())
                .privateKey(rsaKeyProperties.rsaPrivateKey())
                .build();

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    ////    to manage the cors
    @Bean(name = "myWebsiteConfigurationSource")
    CorsConfigurationSource myWebsiteConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT", "HEAD", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean(name = "apiConfigurationSource")
    CorsConfigurationSource apiConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("POST"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                // ...
//                .csrf((csrf) -> csrf
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
//                )
//                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
//        return http.build();
//    }
//}
//
//    final class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
//        private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();
//
//        @Override
//        public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
//            /*
//             * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of
//             * the CsrfToken when it is rendered in the response body.
//             */
//            this.delegate.handle(request, response, csrfToken);
//        }
//
//        @Override
//        public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
//            /*
//             * If the request contains a request header, use CsrfTokenRequestAttributeHandler
//             * to resolve the CsrfToken. This applies when a single-page application includes
//             * the header value automatically, which was obtained via a cookie containing the
//             * raw CsrfToken.
//             */
//            if (StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))) {
//                return super.resolveCsrfTokenValue(request, csrfToken);
//            }
//            /*
//             * In all other cases (e.g. if the request contains a request parameter), use
//             * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
//             * when a server-side rendered form includes the _csrf request parameter as a
//             * hidden input.
//             */
//            return this.delegate.resolveCsrfTokenValue(request, csrfToken);
//        }
//    }
//
//    final class CsrfCookieFilter extends OncePerRequestFilter {
//
//        @Override
//        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//                throws ServletException, IOException {
//            CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
//            // Render the token value to a cookie by causing the deferred token to be loaded
//            csrfToken.getToken();
//
//            filterChain.doFilter(request, response);
//        }
//    }
}

