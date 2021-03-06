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
package org.zalando.stups.fullstop.violation.store.slf4j;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.google.common.collect.Lists;

/**
 * @author  jbellmann
 */
@ConfigurationProperties(prefix = "fullstop.violation.store.slf4j")
public class Slf4jViolationStoreProperties {

    private List<String> loggernames = Lists.newArrayList("fullstop.violations.store");

    public List<String> getLoggernames() {
        return loggernames;
    }

    public void setLoggernames(final List<String> loggernames) {
        this.loggernames = loggernames;
    }

}
