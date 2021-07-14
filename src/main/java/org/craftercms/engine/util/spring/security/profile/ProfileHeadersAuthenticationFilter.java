/*
 * Copyright (C) 2007-2020 Crafter Software Corporation. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.craftercms.engine.util.spring.security.profile;

import java.beans.ConstructorProperties;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.craftercms.engine.util.spring.security.headers.AbstractHeadersAuthenticationFilter;
import org.craftercms.profile.api.AttributeDefinition;
import org.craftercms.profile.api.Profile;
import org.craftercms.profile.api.Tenant;
import org.craftercms.profile.api.exceptions.ProfileException;
import org.craftercms.profile.api.services.ProfileService;
import org.craftercms.profile.api.services.TenantService;
import org.craftercms.security.utils.tenant.TenantsResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isNoneEmpty;

/**
 * Implementation of {@link AbstractHeadersAuthenticationFilter} for Profile
 *
 * @author joseross
 * @since 3.1.5
 */
public class ProfileHeadersAuthenticationFilter extends AbstractHeadersAuthenticationFilter {

    private static final Logger logger = LoggerFactory.getLogger(ProfileHeadersAuthenticationFilter.class);

    protected final ProfileService profileService;

    protected final TenantService tenantService;

    protected final TenantsResolver tenantsResolver;

    @ConstructorProperties({"profileService", "tenantService", "tenantsResolver"})
    public ProfileHeadersAuthenticationFilter(final ProfileService profileService,
                                              final TenantService tenantService,
                                              final TenantsResolver tenantsResolver) {
        // always enabled, for backwards compatibility
        super(null);
        setAlwaysEnabled(true);
        setSupportedPrincipalClass(ProfileUser.class);

        this.profileService = profileService;
        this.tenantService = tenantService;
        this.tenantsResolver = tenantsResolver;
    }

    @Override
    protected Object doGetPreAuthenticatedPrincipal(final HttpServletRequest request) {
        String username = request.getHeader(getUsernameHeaderName());
        String email = request.getHeader(getEmailHeaderName());

        if (isNoneEmpty(username, email)) {
            try {
                String[] tenantNames = tenantsResolver.getTenants();
                Tenant tenant = getSsoEnabledTenant(tenantNames);

                if (tenant != null) {
                    Profile profile = profileService.getProfileByUsername(tenant.getName(), username);
                    if (profile == null) {
                        profile = createProfileWithSsoInfo(username, tenant, request);
                    }

                    return new ProfileUser(profile);
                } else {
                    logger.warn("A SSO login was attempted, but none of the tenants [{}] is enabled for SSO",
                            (Object) tenantNames);
                }
            } catch (ProfileException e) {
                logger.error("Error processing headers authentication for '{}'", username, e);
            }
        }

        return null;
    }

    protected Tenant getSsoEnabledTenant(String[] tenantNames) throws ProfileException {
        for (String tenantName : tenantNames) {
            Tenant tenant = tenantService.getTenant(tenantName);
            if (tenant != null && tenant.isSsoEnabled()) {
                return tenant;
            }
        }
        return null;
    }

    protected Profile createProfileWithSsoInfo(String username, Tenant tenant, HttpServletRequest request)
        throws ProfileException {
        Map<String, Object> attributes = null;
        List<AttributeDefinition> attributeDefinitions = tenant.getAttributeDefinitions();

        String email = request.getHeader(getEmailHeaderName());

        for (AttributeDefinition attributeDefinition : attributeDefinitions) {
            String attributeName = attributeDefinition.getName();
            String attributeValue = request.getHeader(getHeaderPrefix() + attributeName);

            if (StringUtils.isNotEmpty(attributeValue)) {
                if (attributes == null) {
                    attributes = new HashMap<>();
                }

                attributes.put(attributeName, attributeValue);
            }
        }

        logger.info("Creating new profile with SSO info: username={}, email={}, tenant={}, attributes={}", username,
            email, tenant.getName(), attributes);

        return profileService.createProfile(tenant.getName(), username, null, email, true, null, attributes, null);
    }

}
