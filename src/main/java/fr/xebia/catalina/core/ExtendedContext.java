/*
 * Copyright 2002-2008 the original author or authors.
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
package fr.xebia.catalina.core;

import javax.naming.directory.DirContext;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.core.StandardContext;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import fr.xebia.naming.resources.MultiBaseFileDirContext;

/**
 * <p>
 * This extended context search for files (jsp, html, etc) in the default folder tree as well as in a given folder tree called
 * {@link ExtendedContext#alternateDocBase}. This alternate doc base is typically useful with generated jsp files (e.g. by a Content
 * Management System, etc).
 * </p>
 * 
 * @author <a href="mailto:cyrille.leclerc@pobox.com">Cyrille Le Clerc</a>
 */
public class ExtendedContext extends StandardContext {
    
    private static final long serialVersionUID = 1L;
    
    private static transient Log log = LogFactory.getLog(ExtendedContext.class);
    
    /**
     * The alternate document root for this web application.
     */
    protected String alternateDocBase;
    
    protected transient DirContext webAppResources;
    
    public String getAlternateDocBase() {
        return alternateDocBase;
    }
    
    /**
     * Set the alternate document root for this Context. This can be an absolute pathname, a relative pathname, or a URL.
     * 
     * @param docBase The new document root
     */
    public void setAlternateDocBase(String alternateDocBase) {
        this.alternateDocBase = alternateDocBase;
    }
    
    @Override
    public synchronized void start() throws LifecycleException {
        webAppResources = new MultiBaseFileDirContext();
        setResources(webAppResources);
        super.start();
    }
    
    @Override
    public boolean resourcesStart() {
        try {
            if (webAppResources instanceof MultiBaseFileDirContext && alternateDocBase != null) {
                ((MultiBaseFileDirContext)webAppResources).setAlternateDocBase(alternateDocBase);
            }
        } catch (Throwable t) {
            log.error(sm.getString("standardContext.resourcesStart"), t);
            return false;
        }
        return super.resourcesStart();
    }
}
