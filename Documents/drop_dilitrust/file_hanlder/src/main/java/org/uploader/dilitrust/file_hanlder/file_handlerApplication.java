package org.uploader.dilitrust.file_hanlder;


import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.uploader.dilitrust.file_hanlder.health.UploadHealthCheck;
import org.uploader.dilitrust.file_hanlder.resources.UploadResource;

import com.meltmedia.dropwizard.crypto.CryptoBundle;

import io.dropwizard.forms.MultiPartBundle;
import io.dropwizard.server.DefaultServerFactory;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

public class file_handlerApplication extends Application<file_handlerConfiguration> {

    public static void main(final String[] args) throws Exception {
        new file_handlerApplication().run(args);
    }

    @Override
    public String getName() {
        return "file_handler";
    }

    @Override
    public void initialize(final Bootstrap<file_handlerConfiguration> bootstrap) {
        // TODO: application initialization
    	bootstrap.addBundle(new MultiPartBundle());
    	bootstrap.addBundle(new AssetsBundle("/assets", "/", "index.html"));
    	bootstrap.addBundle(CryptoBundle.builder().build());
    }

    @Override
    public void run(final file_handlerConfiguration configuration,
                    final Environment environment) {
        // TODO: implement application
    	final DefaultServerFactory serverFactory =
    			(DefaultServerFactory) configuration.getServerFactory();
    			serverFactory.setApplicationContextPath("/");
    			serverFactory.setJerseyRootPath("/api");
    			
    	final UploadResource resource = new UploadResource(
    	        configuration.getTemplate(),
    	        configuration.getDefaultName()
    	    );
    	final UploadHealthCheck healthCheck =
    	        new UploadHealthCheck(configuration.getTemplate());
    	    environment.healthChecks().register("upload", healthCheck);
    	    //environment.jersey().setUrlPattern("/api/*");
    	    //environment.jersey().register(MultiPartFeature.class);
    	    environment.jersey().register(resource);
    }

}
