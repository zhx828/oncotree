package org.mskcc.oncotree;

import static com.google.common.collect.Lists.newArrayList;

//import org.mskcc.oncotree.oauth2.google.DefaultUserAuthenticationConverter;
//import org.mskcc.oncotree.oauth2.google.GoogleAccessTokenConverter;
//import org.mskcc.oncotree.oauth2.google.GoogleTokenServices;
import org.mskcc.oncotree.oauth2.google.GoogleProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.annotation.Resource;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;

@SpringBootApplication
@EnableSwagger2
@RestController
@EnableOAuth2Client
@EnableAuthorizationServer
@Order(6)
public class OncotreeApplication extends WebSecurityConfigurerAdapter {

    @Autowired
    private Environment env;
    
    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    OAuth2RestTemplate oAuth2RestTemplate;
    
    @RequestMapping({"/user", "/me"})
    public GoogleProfile user(Principal principal) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        GoogleProfile profile = getGoogleProfile();
        return profile;
    }


    private GoogleProfile getGoogleProfile() {
        String url = "https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + oAuth2RestTemplate.getAccessToken();
        ResponseEntity<GoogleProfile> forEntity = oAuth2RestTemplate.getForEntity(url, GoogleProfile.class);
        return forEntity.getBody();
    }
    
    public static void main(String[] args) {
        SpringApplication.run(OncotreeApplication.class, args);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off	
        http.antMatcher("/**")
            .authorizeRequests()
            .antMatchers("/", "/login**", "/webjars/**").permitAll()
            .anyRequest().authenticated()
            .and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
            .and().logout().deleteCookies("remove").logoutUrl("/logout").logoutSuccessUrl("/").permitAll()
            .and().csrf().csrfTokenRepository(csrfTokenRepository())
            .and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
            .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
        
        http.antMatcher("/**")
            .authorizeRequests()
            .antMatchers("/tumorTypes", "/css/**", "/fonts/**", "/js/**").permitAll();

        http
            .formLogin()
            .loginPage("/")
            .defaultSuccessUrl("/")
//            .successHandler(successHandler())
            .permitAll();
        // @formatter:on
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        SimpleUrlAuthenticationSuccessHandler handler = new SimpleUrlAuthenticationSuccessHandler();
        handler.setUseReferer(true);
        return handler;
    }
    
    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration
        extends ResourceServerConfigurerAdapter {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .antMatcher("/me")
                .authorizeRequests().anyRequest().authenticated();
            // @formatter:on
        }
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegi(
        OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    @ConfigurationProperties("github")
    ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("facebook")
    ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("google")
    ClientResources google() {
        return new ClientResources();
    }
//
//    @Bean
//    public GoogleTokenServices tokenServices(ClientResources clientResources) {
//        GoogleTokenServices tokenServices = new GoogleTokenServices();
//        tokenServices
//            .setCheckTokenEndpointUrl("https://www.googleapis.com/oauth2/v1/tokeninfo");
//        tokenServices.setClientId(clientResources.getClient().getClientId());
//        tokenServices.setClientSecret(clientResources.getClient().getClientSecret());
//        tokenServices.setAccessTokenConverter(googleAccessTokenConverter());
//        return tokenServices;
//    }
//
//
//    @Bean
//    public GoogleAccessTokenConverter googleAccessTokenConverter() {
//        GoogleAccessTokenConverter googleAccessTokenConverter = new GoogleAccessTokenConverter();
//
//        googleAccessTokenConverter
//            .setUserTokenConverter(defaultUserAuthenticationConverter());
//
//        return googleAccessTokenConverter;
//    }
//
//    @Bean
//    public DefaultUserAuthenticationConverter defaultUserAuthenticationConverter() {
//        return new DefaultUserAuthenticationConverter();
//    }
    
    @Bean
    public OAuth2ProtectedResourceDetails googleResource(ClientResources clientResources) {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setId("google-oauth-client");
        details.setClientId(clientResources.getClient().getClientId());
        details.setClientSecret(clientResources.getClient().getClientSecret());
        details.setAccessTokenUri(clientResources.getClient().getAccessTokenUri());
        details.setUserAuthorizationUri(env.getProperty("google.userAuthorizationUri"));
        details.setTokenName(env.getProperty("google.authorization.code"));
        String commaSeparatedScopes = env.getProperty("google.auth.scope");
        details.setScope(parseScopes(commaSeparatedScopes));
        details.setUseCurrentUri(false);
        details.setPreEstablishedRedirectUri(env.getProperty("google.preestablished.redirect.url"));
        details.setAuthenticationScheme(AuthenticationScheme.query);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        return details;
    }


    private List parseScopes(String commaSeparatedScopes) {
        List scopes = newArrayList();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }
    
    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilter(github(), "/login/github"));
        filters.add(ssoFilter(google(), "/login/google"));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter(
            path);
        if (path.equals("/login/google")) {
            oAuth2RestTemplate = new OAuth2RestTemplate(googleResource(client),
                oauth2ClientContext);
            facebookFilter.setRestTemplate(oAuth2RestTemplate);
            facebookFilter.setTokenServices(new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId()));
        } else {
            oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(),
                oauth2ClientContext);
            facebookFilter.setRestTemplate(oAuth2RestTemplate);
            facebookFilter.setTokenServices(new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId()));
        }
        return facebookFilter;
    }

    private Filter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
                CsrfToken csrf = (CsrfToken) request
                    .getAttribute(CsrfToken.class.getName());
                if (csrf != null) {
                    Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                    String token = csrf.getToken();
                    if (cookie == null
                        || token != null && !token.equals(cookie.getValue())) {
                        cookie = new Cookie("XSRF-TOKEN", token);
                        cookie.setPath("/");
                        response.addCookie(cookie);
                    }
                }
                filterChain.doFilter(request, response);
            }
        };
    }

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

    @Bean
    ApiInfo apiInfo() {
        ApiInfo apiInfo = new ApiInfo(
            "OncoTree API",
            "OncoTree API definition from cBioPortal, MSKCC",
            "0.0.1",
            "",
            "",
            "",
            "");
        return apiInfo;
    }

    @Bean
    public Docket customImplementation() {
        return new Docket(DocumentationType.SWAGGER_2).apiInfo(apiInfo());
    }

}

class ClientResources {
    private OAuth2ProtectedResourceDetails client = new AuthorizationCodeResourceDetails();
    private ResourceServerProperties resource = new ResourceServerProperties();

    public OAuth2ProtectedResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }
}
