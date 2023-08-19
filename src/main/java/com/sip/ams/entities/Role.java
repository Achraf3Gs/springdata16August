 package com.sip.ams.entities;


 import jakarta.persistence.*; 

 @Entity
 @Table(name = "role")
 public class Role {
     @Id
     @GeneratedValue(strategy = GenerationType.AUTO)
     @Column(name = "role_id")
     private int id;
     @Column(name = "role")
     private String role;
 	public Role(String role) {
		this.role = role;
	}
	public Role() {
		
	}
	
	public int getId() {
 		return id;
 	}
 	public void setId(int id) {
 		this.id = id;
 	}
 	public String getRole() {
 		return role;
 	}
 	public void setRole(String role) {
 		this.role = role;
 	}
 }

