package br.com.todolisttomaz.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.todolisttomaz.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Pegar Auth
        var authorization = request.getHeader("Authorization");
        var authEncoded = authorization.substring("Basic".length()).trim();
        byte[] authDecode = Base64.getDecoder().decode(authEncoded);
        var authString = new String(authDecode);
        String[] authArray = authString.split(":");
        String username = authArray[0];
        String password = authArray[1];

        // Validar Usuário
        var user = this.userRepository.findByUsername(username);
        if (user == null) {
            response.sendError(401);
        } else {
        // Validar senha
            var passwordHash = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if (passwordHash.verified) {
                filterChain.doFilter(request, response);
            } else {
                response.sendError(401);
            }


    }

}}
