package com.sip.ams.configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.sip.ams.entities.User;

import javax.sql.DataSource;
@Configuration

public class SecurityConfiguration {
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
   

    @Value("${spring.queries.users-query}")
    private String usersQuery;
    @Value("${spring.queries.roles-query}")
    private String rolesQuery;
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    
  

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
            .setType(EmbeddedDatabaseType.H2)
            .addScript(JdbcDaoImpl.DEF_AUTHORITIES_BY_USERNAME_QUERY)
            .build();
    }

    @Bean
    public UserDetailsManager users(DataSource dataSource) {
        UserDetails user	 =  User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();
        JdbcUserDetailsManager users = new JdbcUserDetailsManager();
        users.createUser(user);
        users.setDataSource( dataSource);
        return users;
    }

        @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    	http    .authorizeHttpRequests(auth -> auth
    			.requestMatchers("/").permitAll() // accès pour tous users
                .requestMatchers("/login").permitAll() // accès pour tous users
                .requestMatchers("/registration").permitAll() // accès pour tous users
                .requestMatchers("/provider/**").hasAuthority("ADMIN")
                .requestMatchers("/article/**").hasAuthority("USER").anyRequest()
                .authenticated())
                
                .csrf(csrf->csrf.disable())
                
                .formLogin(formLogin->formLogin // l'accès de fait via un formulaire
                .loginPage("/login").failureUrl("/login?error=true") // fixer la page login
                .defaultSuccessUrl("/home") // page d'accueil après login avec succès
                .usernameParameter("email") // paramètres d'authentifications login et password
                .passwordParameter("password"))
                
                .logout(logout->logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // route de deconnexion ici /logut
                .logoutSuccessUrl("/login"))
                .exceptionHandling(exceptionHandling->exceptionHandling // une fois deconnecté redirection vers login
                .accessDeniedPage("/403")); 
    	       http.authenticationProvider(authenticationProvider());
                  return http.build();
    }

   // laisser l'accès aux ressources
        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
          return (web) -> web.ignoring().requestMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**"); 
        }
   
    }


