package org.uploader.dilitrust.file_hanlder.resources;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;

import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.uploader.dilitrust.file_hanlder.api.Uploaded;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.codahale.metrics.annotation.Timed;

@Path("/upload")
@Produces(MediaType.APPLICATION_JSON)
public class UploadResource {
	private final String template;
    private final String defaultName;
    private final AtomicLong counter;
 
    
    public static String encrypt(final String secret, final String data) {

        //byte[] decodedKey = Base64.getDecoder().decode(secret);

        try {
            Cipher cipher = Cipher.getInstance("AES");
            Key originalKey = new SecretKeySpec(secret.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, originalKey);
            byte[] cipherText = cipher.doFinal(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Error occured while encrypting data", e);
        }

    }

    public static String encrypt(final Key secret, final String data) {

        //byte[] decodedKey = Base64.getDecoder().decode(secret);

        try {
            Cipher cipher = Cipher.getInstance("AES");
            //Key originalKey = new SecretKeySpec(secret.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            byte[] cipherText = cipher.doFinal(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Error occured while encrypting data", e);
        }

    }
    public static String decrypt(final String secret,
            final String encryptedString) {


        //byte[] decodedKey = Base64.getDecoder().decode(secret);

        try {
            Cipher cipher = Cipher.getInstance("AES");
            // rebuild key using SecretKeySpec
            Key originalKey = new SecretKeySpec(Base64.getDecoder().decode(secret), "AES");
            cipher.init(Cipher.DECRYPT_MODE, originalKey);
            byte[] cipherText = cipher.doFinal(Base64.getDecoder().decode(encryptedString));
            return new String(cipherText);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Error occured while decrypting data", e);
        }
    }


    public static Key generateKey() throws NoSuchAlgorithmException {
    	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    	keyGen.init(128); // for example
    	Key secretKey = keyGen.generateKey();
    	return secretKey;
    }
    
    public UploadResource(String template, String defaultName) {
        this.template = template;
        this.defaultName = defaultName;
        this.counter = new AtomicLong();
    }
    
 
    private void writeToFile(InputStream uploadedInputStream, String uploadedFileLocation,String key) throws IOException, 
						    NoSuchAlgorithmException, 
						    NoSuchPaddingException, 
						    InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
    {
        int read;
        String algorithm = "AES";
        String transformation = "AES";
		Key cleSecret = new SecretKeySpec(key.getBytes(), algorithm);
		Cipher cipher;
		cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.ENCRYPT_MODE, cleSecret);
        final int BUFFER_LENGTH = 1024;
        final byte[] buffer = new byte[BUFFER_LENGTH];
        OutputStream out = new FileOutputStream(new File(uploadedFileLocation));
        while ((read = uploadedInputStream.read(buffer)) != -1) {
        	byte[] outputBytes = cipher.doFinal(buffer);
            out.write(outputBytes, 0, read);
        }
        out.flush();
        out.close();
    }
    
    private byte[] readToFile(String uploadedFileLocation,String key) throws IOException, 
    NoSuchAlgorithmException, 
    NoSuchPaddingException, 
    InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
{
    	
    	
		int read;
		String algorithm = "AES";
		String transformation = "AES";
		Key cleSecret = new SecretKeySpec(key.getBytes(), algorithm);
		Cipher cipher;
		cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.DECRYPT_MODE, cleSecret);
		StringBuilder sb = new StringBuilder();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(uploadedFileLocation),"utf-8"))) {

            // read line by line
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            
        } catch (IOException e) {
            System.err.format("IOException: %s%n", e);
        }
        byte[] out=cipher.doFinal(sb.toString().getBytes());
		//in.close();
		return out;
}
    @GET
    @Timed
    public Uploaded upload(@QueryParam("name") Optional<String> name) {
        final String value = String.format(template, name.orElse(defaultName));
        return new Uploaded(counter.incrementAndGet(), value);
    }
    
    @POST
    @Timed
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Uploaded upload(@FormDataParam("file") final InputStream fileInputStream,
            @FormDataParam("file") final FormDataContentDisposition fileDetails) {
    	String fileName=fileDetails.getFileName();
    	java.nio.file.Path outputPath = FileSystems.getDefault().getPath("uploaded", fileName);
    	long size=0;
    	try {
    		String key = "Clédesécurité123";
    		Key genKey=UploadResource.generateKey();
    		StringBuilder sb = new StringBuilder();
    		try (BufferedReader br = new BufferedReader(new InputStreamReader(fileInputStream,"utf-8"))) {
    			String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
    		}catch(IOException e) {
                System.err.format("IOException: %s%n", e);
            }
    		String encrypted=UploadResource.encrypt(genKey,sb.toString());
    		InputStream inputEncypted=new ByteArrayInputStream(encrypted.getBytes());
    		Files.copy(inputEncypted, outputPath,StandardCopyOption.REPLACE_EXISTING);
    		fileName=fileName+" uploaded and encrypted correctly with key : encode= "
    				+ " " +Base64.getEncoder().encodeToString(genKey.getEncoded());
    		return new Uploaded(counter.incrementAndGet(), fileName);
    	}catch(Exception e) {
    		e.printStackTrace();
    		fileName=fileName+" couldn't be uploaded correctly "+ e.getMessage()+" array size "+size;
    		return new Uploaded(counter.incrementAndGet(), fileName);
    	}
    }
    
  //OutputStream out=readToFile(pathBuild.toString(),key);
	/*Key cleSecret = new SecretKeySpec(key.getBytes(), algorithm);
	Cipher cipher = Cipher.getInstance(transformation);
	cipher.init(Cipher.DECRYPT_MODE, cleSecret);
    String dValue = null;
    String valueToDecrypt = value.trim();
    for (int i = 0; i < ITERATIONS; i++) {
      byte[] decordedValue = new sun.misc.BASE64Decoder().decodeBuffer(valueToDecrypt);
      byte[] decValue = c.doFinal(decordedValue);
      dValue = new String(decValue).substring(sunbird_encryption.length());
      valueToDecrypt = dValue;
    }
    return dValue; ,
    		@HeaderParam("cle") String cle*/
    @GET
    @Timed
    @Path("/download")
    public Response download(@QueryParam("name") Optional<String> nameOP) {
    	StringBuilder pathBuild=new StringBuilder("uploaded\\");
    	String name=nameOP.orElse(defaultName);
    	pathBuild.append(name);
    	try {
    		
	    	InputStream input = new FileInputStream(pathBuild.toString());
	    	String key = "Clédesécurité123";
	    	StringBuilder sb = new StringBuilder();
    		try (BufferedReader br = new BufferedReader(new InputStreamReader(input,"utf-8"))) {
    			String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
    		}catch(IOException e) {
                System.err.format("IOException: %s%n", e);
            }
	    	String decrypted=UploadResource.decrypt(key,sb.toString());
	    	InputStream in=new ByteArrayInputStream(decrypted.getBytes());
	    	return Response.ok(in)
	                .header(HttpHeaders.CONTENT_DISPOSITION, 
	                        "attachment; filename=\""+name+"\"")
	                .build();
    	}catch(Exception e) {
    		e.printStackTrace();	
    		return Response.status(404).build();
    	}
    }
    
    @GET
    @Timed
    @Path("/downloader")
    public Response download(@QueryParam("name") Optional<String> nameOP,
    		@HeaderParam("cle") String key) {
    	StringBuilder pathBuild=new StringBuilder("uploaded\\");
    	String name=nameOP.orElse(defaultName);
    	pathBuild.append(name);
    	try {
    		
	    	InputStream input = new FileInputStream(pathBuild.toString());
	    	StringBuilder sb = new StringBuilder();
    		try (BufferedReader br = new BufferedReader(new InputStreamReader(input,"utf-8"))) {
    			String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
    		}catch(IOException e) {
                System.err.format("IOException: %s%n", e);
            }
	    	String decrypted=UploadResource.decrypt(key,sb.toString());
	    	InputStream in=new ByteArrayInputStream(decrypted.getBytes());
	    	return Response.ok(in)
	                .header(HttpHeaders.CONTENT_DISPOSITION, 
	                        "attachment; filename=\""+name+"\"")
	                .build();
    	}catch(Exception e) {
    		e.printStackTrace();	
    		return Response.status(404).build();
    	}
    }
}
