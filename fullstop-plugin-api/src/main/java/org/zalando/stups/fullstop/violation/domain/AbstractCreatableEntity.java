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

package org.zalando.stups.fullstop.violation.domain;

import com.google.common.base.Objects;
import org.joda.time.DateTime;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.EntityListeners;
import javax.persistence.MappedSuperclass;

/**
 * @author  ahartmann
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class AbstractCreatableEntity extends AbstractEntity {

    @CreatedDate
    @Column(nullable = false)
    private DateTime created;

    @CreatedBy
    @Column(nullable = false)
    protected String createdBy;

    public DateTime getCreated() {
        return created;
    }

    public void setCreated(final DateTime created) {
        this.created = created;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(final String createdBy) {
        this.createdBy = createdBy == null ? null : createdBy.trim();
    }

    @Override
    protected void addToStringFields(final Objects.ToStringHelper helper) {
        helper.add("created", created);
        helper.add("createdBy", createdBy);
    }
}
