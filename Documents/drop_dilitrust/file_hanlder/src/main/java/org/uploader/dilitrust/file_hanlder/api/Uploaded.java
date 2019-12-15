package org.uploader.dilitrust.file_hanlder.api;

import org.hibernate.validator.constraints.Length;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Uploaded {
	 private long id;

	    @Length(max = 300)
	    private String content;

	    public Uploaded() {
	        // Jackson deserialization
	    }

	    public Uploaded(long id, String content) {
	        this.id = id;
	        this.content = content;
	    }

	    @JsonProperty
	    public long getId() {
	        return id;
	    }

	    @JsonProperty
	    public String getContent() {
	        return content;
	    }
}
