package com.geardao.JWTDemo.user;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {
	
    private ApplicationUserRepository applicationUserRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserController(ApplicationUserRepository applicationUserRepository,
                          BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.applicationUserRepository = applicationUserRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping("/sign-up")
    public ResponseEntity<ApplicationUser> signUp(@RequestBody ApplicationUser user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        ApplicationUser result = applicationUserRepository.save(user);
        return new ResponseEntity<ApplicationUser>(result, HttpStatus.CREATED);
    }
    
    @GetMapping("/get-all")
    public ResponseEntity<List<ApplicationUser>> getAllUser(){
    	List<ApplicationUser> result = applicationUserRepository.findAll();
    	return new ResponseEntity<List<ApplicationUser>>(result,HttpStatus.OK);
    }
    
    @GetMapping("/hello")
    public String hello() {
    	return "hello";
    }
}
