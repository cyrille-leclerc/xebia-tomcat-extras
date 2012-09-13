/*
 * Copyright 2008-2012 Xebia and the original author or authors.
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
package fr.xebia.catalina.realm;

import org.apache.catalina.Context;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.CombinedRealm;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Realm implementation in which all the resources are secured and require the given role.
 * <p/>
 * Default required role is 'user'.
 *
 * Configuration sample, extract of <code>server.xml</code>:
 * <pre><code>
 * &lt;Realm className="fr.xebia.catalina.realm.PrivateRealm"&gt;
 *     &lt;Realm className="org.apache.catalina.realm.MemoryRealm" /&gt;
 * &lt;/Realm&gt;
 * </code></pre>
 *
 * @author <a href="mailto:cleclerc@xebia.fr">Cyrille Le Clerc</a>
 */
public class PrivateRealm extends CombinedRealm implements Realm {

    private static Log log = LogFactory.getLog(PrivateRealm.class);

    private String requiredRole = "user";

    @Override
    public SecurityConstraint[] findSecurityConstraints(Request request, Context context) {

        if (log.isDebugEnabled())
            log.debug(" return default security constraint ");

        SecurityCollection securityCollection = new SecurityCollection("all");
        securityCollection.addPattern("/*");
        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.addCollection(securityCollection);
        securityConstraint.addAuthRole(requiredRole);

        return new SecurityConstraint[]{securityConstraint};
    }

    public String getRequiredRole() {
        return requiredRole;
    }

    public void setRequiredRole(String requiredRole) {
        this.requiredRole = requiredRole;
    }
}
