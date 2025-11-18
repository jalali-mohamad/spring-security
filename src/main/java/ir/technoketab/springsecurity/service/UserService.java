package ir.technoketab.springsecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ir.technoketab.springsecurity.model.Dtos.UserDto;
import ir.technoketab.springsecurity.model.Role;
import ir.technoketab.springsecurity.model.User;
import ir.technoketab.springsecurity.repository.RoleRepository;
import ir.technoketab.springsecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ObjectMapper objectMapper;

    @Transactional
    public User createUser(UserDto user) {
        Role role = roleRepository.findByName(user.getRole());
        if (role == null) {
            role = new Role();
            role.setName(user.getRole());
            roleRepository.save(role);
        }
        User userEntity = new User();
        userEntity.setUsername(user.getUsername());
        userEntity.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userEntity.setRole(role);
        return userRepository.save(userEntity);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
