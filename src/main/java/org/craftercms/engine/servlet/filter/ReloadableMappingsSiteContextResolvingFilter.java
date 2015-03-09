package org.craftercms.engine.servlet.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import javax.annotation.PostConstruct;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.craftercms.core.exception.CrafterException;
import org.craftercms.engine.service.context.SiteContext;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.core.io.Resource;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Filter that resolves the current site name from a mapping of the request domain name to site name. These mappings
 * are dynamic in that anytime while Engine is running they can change (ones can be added and others removed). The
 * {@link #reloadMappings()} method then can be called to reload the mappings.
 *
 * @author avasquez
 */
public class ReloadableMappingsSiteContextResolvingFilter extends AbstractSiteContextResolvingFilter {

    private static final Log logger = LogFactory.getLog(ReloadableMappingsSiteContextResolvingFilter.class);

    protected Resource mappingsFile;
    protected volatile Properties mappings;

    @Required
    public void setMappingsFile(Resource mappingsFile) {
        this.mappingsFile = mappingsFile;
    }

    @PostConstruct
    public void init() {
        loadMappings();
    }

    public void reloadMappings() throws CrafterException {
        loadMappings();
        unregisterSiteContextsWithNoMapping();
    }

    @Override
    protected String getSiteNameFromRequest(ServletWebRequest request) {
        String domainName = request.getRequest().getServerName();

        if (mappings.containsKey(domainName)) {
            return (String)mappings.get(domainName);
        } else {
            logger.warn("No site mapping found for domain name " + domainName);

            return null;
        }
    }

    protected void loadMappings() throws CrafterException {
        Properties newMappings = new Properties();

        try {
            newMappings.load(mappingsFile.getInputStream());
        } catch (IOException e) {
            throw new CrafterException("Unable to load domain name to site name mappings from " + mappingsFile, e);
        }

        logger.info("Domain name to site name mappings loaded from " + mappingsFile);

        mappings = newMappings;
    }

    protected void unregisterSiteContextsWithNoMapping() {
        List<SiteContext> contextsToUnregister = new ArrayList<>();
        Collection<Object> currentSiteNames = mappings.values();

        for (SiteContext context : siteContextRegistry.list()) {
            String siteName = context.getSiteName();
            if (!siteName.equals(fallbackSiteName) && !currentSiteNames.contains(siteName)) {
                contextsToUnregister.add(context);
            }
        }

        for (SiteContext context : contextsToUnregister) {
            siteContextRegistry.unregister(context.getSiteName());
        }
    }

}