package com.sip.ams.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import javax.validation.constraints.NotBlank;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Entity

public class Article {
	@Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @NotBlank(message = "Label is mandatory")
    @Column(name = "label")
    private String label;
    
    
 
    @Column(name = "price")
    private float price;

    public Article() {}

    public Article(String label, float price) {
        this.price = price;
        this.label = label;
        }

    public void setId(long id) {
        this.id = id;
    }

    public long getId() {
        return id;
    }

	public String getLabel() {
		return label;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public float getPrice() {
		return price;
	}

	public void setPrice(float price) {
		this.price = price;
	}

	
	/**** Many To One ****/
	
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "provider_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Provider provider;
	
	
	public Provider getProvider() {
    	return provider;
    }
    
    public void setProvider(Provider provider) {
    	this.provider=provider;
    }  
    
}

