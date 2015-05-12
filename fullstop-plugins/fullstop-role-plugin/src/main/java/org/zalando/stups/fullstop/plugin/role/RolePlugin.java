/**
 * Copyright 2015 Zalando SE
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zalando.stups.fullstop.plugin.role;

import static java.lang.String.format;

import static org.zalando.stups.fullstop.events.CloudtrailEventSupport.getAccountId;
import static org.zalando.stups.fullstop.events.CloudtrailEventSupport.getRegionAsString;
import static org.zalando.stups.fullstop.events.CloudtrailEventSupport.readRoleName;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Component;

import org.zalando.stups.fullstop.aws.ClientProvider;
import org.zalando.stups.fullstop.plugin.AbstractFullstopPlugin;
import org.zalando.stups.fullstop.violation.Violation;
import org.zalando.stups.fullstop.violation.ViolationStore;

import com.amazonaws.services.cloudtrail.processinglibrary.model.CloudTrailEvent;
import com.amazonaws.services.cloudtrail.processinglibrary.model.CloudTrailEventData;

/**
 * @author  ljaeckel
 */
@Component
public class RolePlugin extends AbstractFullstopPlugin {

    private static final Logger LOG = LoggerFactory.getLogger(RolePlugin.class);

    private static final String EVENT_SOURCE = "iam.amazonaws.com";

    private static final String CREATE_ROLE_EVENT_NAME = "CreateRole";
    private static final String DELETE_ROLE_EVENT_NAME = "DeleteRole";

    private static final String ATTACH_ROLE_POLICY_EVENT_NAME = "AttachRolePolicy";
    private static final String UPDATE_ROLE_EVENT_NAME = "UpdateAssumeRolePolicy";
    private static final String PUT_ROLE_POLICY_EVENT_NAME = "PutRolePolicy";

    private static final List<String> ROLES = Arrays.asList("Shibboleth-Administrator", "Shibboleth-PowerUser",
            "Shibboleth-PowerUserUS", "Shibboleth-ReadOnly");

    private final ClientProvider cachingClientProvider;
    private final ViolationStore violationStore;

    @Autowired
    public RolePlugin(final ClientProvider cachingClientProvider, final ViolationStore violationStore) {
        this.cachingClientProvider = cachingClientProvider;
        this.violationStore = violationStore;
    }

    @Override
    public boolean supports(final CloudTrailEvent event) {
        CloudTrailEventData cloudTrailEventData = event.getEventData();
        String eventSource = cloudTrailEventData.getEventSource();

        return eventSource.equals(EVENT_SOURCE);
    }

    @Override
    public void processEvent(final CloudTrailEvent event) {

        for (String roleName : readRoleName(event.getEventData().getRequestParameters())) {

            if (ROLES.contains(roleName)) {

                switch (event.getEventData().getEventName()) {

                    case CREATE_ROLE_EVENT_NAME : // TODO: Das Anlegen neuer Rollen erlauben?
                        violationStore.save(new Violation(getAccountId(event), getRegionAsString(event),
                                format("New role with name %s was created.", roleName)));
                        break;

                    case ATTACH_ROLE_POLICY_EVENT_NAME :
                        violationStore.save(new Violation(getAccountId(event), getRegionAsString(event),
                                format("New role policy was attached to role %s.", roleName)));
                        break;

                    case UPDATE_ROLE_EVENT_NAME :
                        violationStore.save(new Violation(getAccountId(event), getRegionAsString(event),
                                format("Policy for role %s was updated.", roleName)));
                        break;

                    case DELETE_ROLE_EVENT_NAME :
                        violationStore.save(new Violation(getAccountId(event), getRegionAsString(event),
                                format("Role with name %s was deleted.", roleName)));
                        break;

                    case PUT_ROLE_POLICY_EVENT_NAME :

                        // TODO:
                        break;

                    default :
                        break;
                }

            }

        }

    }

}
