/*
 * Copyright (C) 2007-2024 Crafter Software Corporation. All Rights Reserved.
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

package org.craftercms.engine.controller.rest;

import org.craftercms.commons.validation.annotations.param.EsapiValidatedParam;
import org.craftercms.commons.validation.annotations.param.ValidExistingContentPath;
import org.craftercms.core.controller.rest.CrafterRestController;
import org.craftercms.core.controller.rest.RestControllerBase;
import org.craftercms.engine.service.UrlTransformationService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.beans.ConstructorProperties;

import static org.craftercms.commons.validation.annotations.param.EsapiValidationType.ALPHANUMERIC;

/**
 * REST controller to access the URL transformation service.
 *
 * @author joseross
 */
@Validated
@CrafterRestController
@RequestMapping(RestControllerBase.REST_BASE_URI + SiteUrlController.URL_ROOT)
public class SiteUrlController extends RestControllerBase {

    public static final String URL_ROOT = "/site/url";
    public static final String URL_TRANSFORM = "/transform";

    protected final UrlTransformationService urlTransformationService;

    @ConstructorProperties({"urlTransformationService"})
    public SiteUrlController(final UrlTransformationService urlTransformationService) {
        this.urlTransformationService = urlTransformationService;
    }

    @GetMapping(URL_TRANSFORM)
    public String transformUrl(@EsapiValidatedParam(type = ALPHANUMERIC) @RequestParam String transformerName,
                               @ValidExistingContentPath
                               @RequestParam String url) {
        return urlTransformationService.transform(transformerName, url);
    }

}
