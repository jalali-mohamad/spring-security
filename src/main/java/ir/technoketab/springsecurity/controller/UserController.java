package ir.technoketab.springsecurity.controller;

import ir.technoketab.springsecurity.model.Dtos.UserDto;
import ir.technoketab.springsecurity.model.User;
import ir.technoketab.springsecurity.service.JwtTokenService;
import ir.technoketab.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;

    @PostMapping("auth/users/register")
    public User register(@RequestBody UserDto userDto) {
        return userService.createUser(userDto);
    }

    @GetMapping("users")
    public List<User> getUsers() {
        return userService.getAllUsers();
    }

    @PostMapping("login")
    public String login(@RequestBody UserDto userDto) {
        Authentication authentication =  authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userDto.getUsername(), userDto.getPassword())
        );
        if (authentication.isAuthenticated()) {
            return jwtTokenService.generateToken(userDto.getUsername());
        }else {
            return "fail";
        }
    }
}
