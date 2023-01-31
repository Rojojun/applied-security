package com.rojojun.securitymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage")    //누구나 접근이 가능하도록 해야함
                .defaultSuccessUrl("/") //인증이 성공시 Default로 가는 URL
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    // 익명클래스를 사용하여 전달하는 방식
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // Log로 대체 예정 ->
                        System.out.println("authentication" + authentication.getName());    //인증에 성공한 유저의 이름을 반환
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception" + exception.getMessage());   //인증 실패에 대한 예외 메시지 반환
                        response.sendRedirect("/loginPage");
                    }
                })
                .permitAll();
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    // 별도로 로그아웃에 대한 다른 작업을 원할 때 사용
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();           // 세션 무효화 작업
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");        // 기본은 로그아웃페이지로 이동이나, 로그아웃이 성공될 때 출력되는 다른 페이지로 만들 수도 있음
                    }
                })
                .deleteCookies("remember-me");
        http
                .rememberMe()
                .rememberMeParameter("remeber")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin();
        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true) // 방법 1: 동시 로그인 차단, 방법 2 :기존세션 만료 (default, false)
        ;
        http
                .sessionManagement()
                .sessionFixation().none() //해커에 침입에 대응 X
        ;

        // 최대 세션의 허용에 대한 확인

        http
                .authorizeHttpRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
        .and()
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true) //인증예외를 발생시켜서 인증을 실패하도록 만들어버림 첫번째 사용자만 로그인 되도록함
                //.maxSessionsPreventsLogin(false) //세션만료를 시켜 두번째 사용자가 로그인 되도록함

        ;
        return http.build();
    }
}
