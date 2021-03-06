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
package org.zalando.stups.fullstop.plugin;

import static java.util.stream.Collectors.toList;

import static org.assertj.core.api.Assertions.assertThat;

import static org.mockito.Mockito.spy;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.assertj.core.api.Assertions;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import org.mockito.Mockito;

import org.zalando.stups.fullstop.aws.ClientProvider;
import org.zalando.stups.fullstop.events.TestCloudTrailEventData;
import org.zalando.stups.fullstop.violation.SysOutViolationStore;
import org.zalando.stups.fullstop.violation.ViolationStore;

import com.amazonaws.services.cloudtrail.processinglibrary.model.CloudTrailEvent;
import com.amazonaws.services.cloudtrail.processinglibrary.model.internal.UserIdentity;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.SecurityGroup;

import com.google.common.collect.Lists;

/**
 * @author  jbellmann
 */
public class RunInstancePluginTest {

    private ClientProvider clientProvider;
    private ViolationStore violationStore;

    @Before
    public void setUp() {
        clientProvider = Mockito.mock(ClientProvider.class);
        violationStore = new SysOutViolationStore();
        violationStore = Mockito.spy(violationStore);
    }

    @Test
    public void hasOnlyPrivateIp() {
        CloudTrailEvent event = new CloudTrailEvent(new TestCloudTrailEventData("/responseElements.json"), null);

        RunInstancePlugin plugin = new TestRunInstancePlugin(clientProvider, violationStore);

        Assertions.assertThat(plugin.hasPublicIp(event)).isFalse();

    }

    @Test
    public void filteringSecurityGroups() {

        RunInstancePlugin plugin = new TestRunInstancePlugin(clientProvider, violationStore);

        Set<String> result = plugin.getPorts(getSecurityGroupsForTesting().get());
        Assertions.assertThat(result).isNotEmpty();

    }

    // TODO
    @Ignore
    @Test
    public void testSecurityGroupFiltering() {
        Optional<List<SecurityGroup>> secGroups = getSecurityGroupsForTesting();
        Predicate<IpPermission> filter = IpPermissionPredicates.withToPort(443).negate().and(IpPermissionPredicates
                    .withToPort(22).negate());

        List<SecurityGroup> filteredSecGroups = secGroups.get().stream()
                                                         .filter(SecurityGroupPredicates.anyMatch(filter)).collect(
                                                             toList());

        System.out.println(filteredSecGroups.size());
        assertThat(filteredSecGroups).isEmpty();
    }

    @Ignore
    @Test
    public void testIpPermissionFiltering() {
        Optional<List<SecurityGroup>> secGroups = getSecurityGroupsForTesting();

        Predicate<IpPermission> filter = IpPermissionPredicates.withToPort(443).negate().and(IpPermissionPredicates
                    .withToPort(22).negate());

        Assertions.assertThat(secGroups.isPresent()).isTrue();

        for (SecurityGroup group : secGroups.get()) {
            List<IpPermission> permissionsFiltered = group.getIpPermissions().stream().filter(filter).collect(toList());
            List<String> filtered = permissionsFiltered.stream().map(toPortToString()).collect(Collectors.toList());
            System.out.println(filtered);
        }

        System.out.println(secGroups.get().size());
        assertThat(secGroups.get()).isEmpty();
    }

    public static Function<IpPermission, String> toPortToString() {
        return new Function<IpPermission, String>() {

            @Override
            public String apply(final IpPermission t) {
                return t.getToPort().toString();
            }
        };
    }

    @Test
    public void runInstancePluginTestWithSubclass() {

        // prepare
        RunInstancePlugin plugin = new TestRunInstancePlugin(clientProvider, violationStore);
        UserIdentity userIdentity = Mockito.mock(UserIdentity.class);
        Mockito.when(userIdentity.getAccountId()).thenReturn("1234567");

        TestCloudTrailEventData eventData = new TestCloudTrailEventData("/responseElements.json");
        eventData = spy(eventData);
        Mockito.when(eventData.getUserIdentity()).thenReturn(userIdentity);

        CloudTrailEvent event = new CloudTrailEvent(eventData, null);

        // test
        plugin.processEvent(event);

        // verify
// verify(violationStore, atLeastOnce()).save(Mockito.any());
    }

    /**
     * Prepare some {@link SecurityGroup}s.
     *
     * @return
     */
    protected static Optional<List<SecurityGroup>> getSecurityGroupsForTesting() {
        List<SecurityGroup> result = Lists.newArrayList();
        for (int i = 0; i < 2; i++) {
            SecurityGroup g = new SecurityGroup();
            g.setOwnerId("OWNER_" + i);
            g.setGroupId("GROUP_" + i);

            for (int j = 0; j < 3; j++) {
                IpPermission permission = new IpPermission();
                permission.setToPort(441 + j);
                g.getIpPermissions().add(permission);
            }

            result.add(g);
        }

        return Optional.of(result);
    }

    /**
     * @author  jbellmann
     */
    static class TestRunInstancePlugin extends RunInstancePlugin {

        public TestRunInstancePlugin(final ClientProvider clientProvider, final ViolationStore violationStore) {
            super(clientProvider, violationStore);
        }

        @Override
        protected Optional<List<SecurityGroup>> getSecurityGroupsForIds(final List<String> securityGroupIds,
                final CloudTrailEvent event) {

            return getSecurityGroupsForTesting();
        }

    }

}
