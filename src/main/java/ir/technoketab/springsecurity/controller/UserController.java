package ir.technoketab.springsecurity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.technoketab.springsecurity.model.Dtos.UserDto;
import ir.technoketab.springsecurity.model.User;
import ir.technoketab.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("auth/users/register")
    public User register(@RequestBody UserDto userDto) {
        return userService.createUser(userDto);
    }

    @GetMapping("users")
    public List<User> getUsers() {
        return userService.getAllUsers();
    }
}
