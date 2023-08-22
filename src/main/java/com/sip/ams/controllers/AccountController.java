package com.sip.ams.controllers;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.sip.ams.entities.Provider;
import com.sip.ams.entities.User;
import com.sip.ams.entities.Role;
import com.sip.ams.repositories.RoleRepository;
import com.sip.ams.repositories.UserRepository;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import jakarta.mail.MessagingException;
import java.io.IOException;

@Controller
@RequestMapping("/accounts/")

public class AccountController {

	@Autowired
    private JavaMailSender javaMailSender;

	
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	
	@Autowired
    public AccountController(UserRepository userRepository,RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }
	
	@GetMapping("list")
    public String listUsers(Model model) {
    	
    	List<User> users = (List<User>) userRepository.findAll();
    	long nbr =  userRepository.count();
    	if(users.size()==0)
    		users = null;
        model.addAttribute("users", users);
        model.addAttribute("nbr", nbr);
        return "user/listUsers";
    }
	
	@GetMapping("enable/{id}/{email}")
	//@ResponseBody
    public String enableUserAcount(@PathVariable ("id") int id, 
    		@PathVariable ("email") String email) {
    	
		 sendEmail(email, true);
		 User user = userRepository.findById(id).orElseThrow(()->new IllegalArgumentException("Invalid User Id:" + id));
	     user.setActive(1);
	     userRepository.save(user);
    	return "redirect:../../list";
    }
	
	@GetMapping("disable/{id}/{email}")
	//@ResponseBody
	public String disableUserAcount(@PathVariable ("id") int id, 
    		@PathVariable ("email") String email) {
    	
		 sendEmail(email, false);
		 
		 User user = userRepository.findById(id).orElseThrow(()->new IllegalArgumentException("Invalid User Id:" + id));
	     user.setActive(0);
	     userRepository.save(user);
    	return "redirect:../../list";
    }

	@PostMapping("updateRole")
	//@ResponseBody
	public String UpdateUserRole(@RequestParam ("id") int id,
			@RequestParam ("newrole")String newRole
			) {
    	
		 User user = userRepository.findById(id).orElseThrow(()->new IllegalArgumentException("Invalid User Id:" + id));
	     
		 
		Role userRole = roleRepository.findByRole(newRole);
		 
	     user.setRoles(new HashSet<Role>(Arrays.asList(userRole)));
	     
	     userRepository.save(user);
    	return "redirect:list";
    }
	  void sendEmail(String email, boolean state) {

	        SimpleMailMessage msg = new SimpleMailMessage();
	        msg.setTo(email);
	        if(state == true)
	        {
	        msg.setSubject("Account Has Been Activated");
	        msg.setText("Hello, Your account has been activated. "
	        		+ 
	        		"You can log in : http://127.0.0.1:81/login"
	        		+ " \n Best Regards!");
	        }
	        else
	        {
	        	msg.setSubject("Account Has Been disactivated");
	            msg.setText("Hello, Your account has been disactivated.");
	        }
	        javaMailSender.send(msg);

	    }
		
	    
	}



