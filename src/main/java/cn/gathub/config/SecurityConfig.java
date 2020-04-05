package cn.gathub.config;

import cn.gathub.config.auth.*;
import cn.gathub.config.auth.jwt.JwtAuthenticationTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) // 开发方法级别权限控制
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 动态加载用户和权限数据使用
    @Resource
    MyUserDetailsService myUserDetailsService;

    // 记住我保存数据库使用
    @Resource
    private DataSource datasource;

    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    // 动态加载资源鉴权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
                .disable() // 禁用跨站csrf攻击防御
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // 解决CSRF跨站攻击防护，浏览器向服务端发送的HTTP请求，都要将CSRF token带上，服务端校验通过才能正确的响应
//                .ignoringAntMatchers("/authentication")

//                .and()
                .cors() // 跨域访问

                .and()
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)

                .authorizeRequests()
                .antMatchers("/authentication", "/refreshtoken").permitAll() // 不需要通过登录验证就可以被访问的资源路径
                .antMatchers("/index").authenticated()
                .anyRequest().access("@rabcService.hasPermission(request, authentication)") // 动态加载资源鉴权，anyRequest对所有请求生效

                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 不会创建或使用任何session。适合于接口型的无状态应用，该方式节省资源。（前后端分离使用）
    }

    // 动态加载用户权限数据
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        // 将项目中静态资源路径开放出来
        web.ignoring().antMatchers("/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // 使用这种方法实现的效果等同于注入一个CorsFilter过滤器。
    @Bean
    CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8080")); // 想让8080访问
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.applyPermitDefaultValues();

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


}

