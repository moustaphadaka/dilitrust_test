package org.uploader.dilitrust.file_hanlder.health;

import com.codahale.metrics.health.HealthCheck;

public class UploadHealthCheck extends HealthCheck {
    private final String template;

    public UploadHealthCheck(String template) {
        this.template = template;
    }

    @Override
    protected Result check() throws Exception {
        final String saying = String.format(template, "TEST");
        if (!saying.contains("TEST")) {
            return Result.unhealthy("template doesn't include a name");
        }
        return Result.healthy();
    }
}