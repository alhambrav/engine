/*
 * Copyright (C) 2007-2013 Crafter Software Corporation.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.craftercms.engine.service.context;

import java.net.URLClassLoader;
import java.util.Arrays;

import org.apache.commons.configuration.HierarchicalConfiguration;
import org.craftercms.core.exception.CrafterException;
import org.craftercms.core.service.ContentStoreService;
import org.craftercms.core.service.Context;
import org.craftercms.core.url.UrlTransformationEngine;
import org.craftercms.engine.scripting.ScriptFactory;
import org.craftercms.engine.service.PreviewOverlayCallback;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfig;

/**
 * Wrapper for a {@link Context} that adds properties specific to Crafter Engine.
 *
 * @author Alfonso Vásquez
 */
public class SiteContext {

    private static ThreadLocal<SiteContext> threadLocal = new ThreadLocal<>();

    protected ContentStoreService storeService;
    protected String siteName;
    protected Context context;
    protected boolean fallback;
    protected String staticAssetsPath;
    protected String templatesPath;
    protected String restScriptsPath;
    protected String controllerScriptsPath;
    protected String[] configPaths;
    protected String[] applicationContextPaths;
    protected String groovyClassesPath;
    protected FreeMarkerConfig freeMarkerConfig;
    protected UrlTransformationEngine urlTransformationEngine;
    protected PreviewOverlayCallback overlayCallback;
    protected ScriptFactory scriptFactory;
    protected HierarchicalConfiguration config;
    protected ConfigurableApplicationContext applicationContext;
    protected URLClassLoader classLoader;
    protected Scheduler scheduler;

    /**
     * Returns the context for the current thread.
     */
    public static SiteContext getCurrent() {
        return threadLocal.get();
    }

    /**
     * Sets the context for the current thread.
     */
    public static void setCurrent(SiteContext current) {
        threadLocal.set(current);
    }

    /**
     * Removes the context from the current thread.
     */
    public static void clear() {
        threadLocal.remove();
    }

    public ContentStoreService getStoreService() {
        return storeService;
    }

    public void setStoreService(ContentStoreService storeService) {
        this.storeService = storeService;
    }

    public String getSiteName() {
        return siteName;
    }

    public void setSiteName(String siteName) {
        this.siteName = siteName;
    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    public boolean isFallback() {
        return fallback;
    }

    public void setFallback(boolean fallback) {
        this.fallback = fallback;
    }

    public String getStaticAssetsPath() {
        return staticAssetsPath;
    }

    public void setStaticAssetsPath(String staticAssetsPath) {
        this.staticAssetsPath = staticAssetsPath;
    }

    public String getTemplatesPath() {
        return templatesPath;
    }

    public void setTemplatesPath(String templatesPath) {
        this.templatesPath = templatesPath;
    }

    public String getRestScriptsPath() {
        return restScriptsPath;
    }

    public void setRestScriptsPath(String restScriptsPath) {
        this.restScriptsPath = restScriptsPath;
    }

    public String getControllerScriptsPath() {
        return controllerScriptsPath;
    }

    public void setControllerScriptsPath(String controllerScriptsPath) {
        this.controllerScriptsPath = controllerScriptsPath;
    }

    public String[] getConfigPaths() {
        return configPaths;
    }

    public void setConfigPaths(String[] configPaths) {
        this.configPaths = configPaths;
    }

    public String[] getApplicationContextPaths() {
        return applicationContextPaths;
    }

    public void setApplicationContextPaths(String[] applicationContextPaths) {
        this.applicationContextPaths = applicationContextPaths;
    }

    public String getGroovyClassesPath() {
        return groovyClassesPath;
    }

    public void setGroovyClassesPath(String groovyClassesPath) {
        this.groovyClassesPath = groovyClassesPath;
    }

    public FreeMarkerConfig getFreeMarkerConfig() {
        return freeMarkerConfig;
    }

    public void setFreeMarkerConfig(FreeMarkerConfig freeMarkerConfig) {
        this.freeMarkerConfig = freeMarkerConfig;
    }

    public UrlTransformationEngine getUrlTransformationEngine() {
        return urlTransformationEngine;
    }

    public void setUrlTransformationEngine(UrlTransformationEngine urlTransformationEngine) {
        this.urlTransformationEngine = urlTransformationEngine;
    }

    public PreviewOverlayCallback getOverlayCallback() {
        return overlayCallback;
    }

    public void setOverlayCallback(PreviewOverlayCallback overlayCallback) {
        this.overlayCallback = overlayCallback;
    }

    public ScriptFactory getScriptFactory() {
        return scriptFactory;
    }

    public void setScriptFactory(ScriptFactory scriptFactory) {
        this.scriptFactory = scriptFactory;
    }

    public HierarchicalConfiguration getConfig() {
        return config;
    }

    public void setConfig(HierarchicalConfiguration config) {
        this.config = config;
    }

    public ConfigurableApplicationContext getApplicationContext() {
        return applicationContext;
    }

    public void setApplicationContext(ConfigurableApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public URLClassLoader getClassLoader() {
        return classLoader;
    }

    public void setClassLoader(URLClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    public Scheduler getScheduler() {
        return scheduler;
    }

    public void setScheduler(Scheduler scheduler) {
        this.scheduler = scheduler;
    }

    public void destroy() throws CrafterException {
        if (applicationContext != null) {
            try {
                applicationContext.close();
            } catch (Exception e) {
                throw new CrafterException("Unable to close application context", e);
            }
        }
        if (classLoader != null) {
            try {
                classLoader.close();
            } catch (Exception e) {
                throw new CrafterException("Unable to close class loader", e);
            }
        }
        if (scheduler != null) {
            try {
                scheduler.shutdown();
            } catch (SchedulerException e) {
                throw new CrafterException("Unable to shutdown scheduler", e);
            }
        }

        storeService.destroyContext(context);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SiteContext siteContext = (SiteContext) o;

        if (!siteName.equals(siteContext.siteName)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return siteName.hashCode();
    }

    @Override
    public String toString() {
        return "SiteContext{" +
               "siteName='" + siteName + '\'' +
               ", context=" + context +
               ", fallback=" + fallback +
               ", staticAssetsPath='" + staticAssetsPath + '\'' +
               ", templatesPath='" + templatesPath + '\'' +
               ", restScriptsPath='" + restScriptsPath + '\'' +
               ", controllerScriptsPath='" + controllerScriptsPath + '\'' +
               ", configPaths=" + Arrays.toString(configPaths) +
               ", applicationContextPaths=" + Arrays.toString(applicationContextPaths) +
               ", groovyClassesPath='" + groovyClassesPath + '\'' +
               '}';
    }

}
