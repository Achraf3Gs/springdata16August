package com.sip.ams;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.sip.ams.controllers.ArticleController;

import java.io.File;


@SpringBootApplication
public class Amsdata16Application {

	public static void main(String[] args) {
		new File(ArticleController.uploadDirectory).mkdir();
		SpringApplication.run(Amsdata16Application.class, args);
	}

}
