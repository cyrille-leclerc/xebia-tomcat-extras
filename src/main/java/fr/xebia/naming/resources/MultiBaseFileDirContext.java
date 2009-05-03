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
package fr.xebia.naming.resources;

import java.io.File;
import java.io.IOException;

import org.apache.naming.resources.FileDirContext;

import fr.xebia.catalina.core.ExtendedContext;

/**
 * Multi doc base {@link FileDirContext}.
 * 
 * @author <a href="mailto:cyrille.leclerc@pobox.com">Cyrille Le Clerc</a>
 * @see ExtendedContext
 */
public class MultiBaseFileDirContext extends FileDirContext {
    
    protected File alternateBase;
    
    protected String alternateAbsoluteBase;
    
    /**
     * Inspired by {@link FileDirContext#setDocBase(String)}
     * <p/>
     * Set the alternate document root.
     * 
     * @param alternateDocBase The new document root
     * @exception IllegalArgumentException if the specified value is not supported by this implementation
     * @exception IllegalArgumentException if this would create a malformed URL
     */
    public void setAlternateDocBase(String alternateDocBase) {
        
        // Validate the format of the proposed document root
        if (alternateDocBase == null)
            throw new IllegalArgumentException(sm.getString("resources.null"));
        
        // Calculate a File object referencing this document base directory
        alternateBase = new File(alternateDocBase);
        try {
            alternateBase = alternateBase.getCanonicalFile();
        } catch (IOException e) {
            // Ignore
        }
        
        // Validate that the document base is an existing directory
        if (!alternateBase.exists() || !alternateBase.isDirectory() || !alternateBase.canRead())
            throw new IllegalArgumentException(sm.getString("fileResources.base", alternateDocBase));
        this.alternateAbsoluteBase = alternateBase.getAbsolutePath();
    }
    
    /**
     * Adaptation of {@link FileDirContext#file(String)} to look in the {@link FileDirContext#do} and then in {@link #alternateBase}
     */
    @Override
    protected File file(String name) {
        File result = super.file(name);
        if (result != null) {
            return result;
        }
        return fileFromAlternateDocBase(name);
    }
    
    /**
     * Adaptation of {@link FileDirContext#file(String)} using the {@link #alternateBase} instead of the {@link FileDirContext#base}
     * <p/>
     * Return a File object representing the specified normalized context-relative path if it exists and is readable. Otherwise, return
     * <code>null</code>.
     * 
     * @param name Normalized context-relative path (with leading '/')
     * @see FileDirContext#file(String)
     */
    protected File fileFromAlternateDocBase(String name) {
        
        if (alternateBase == null) {
            return null;
        }
        File file = new File(alternateBase, name);
        if (file.exists() && file.canRead()) {
            
            if (allowLinking)
                return file;
            
            // Check that this file belongs to our root path
            String canPath = null;
            try {
                canPath = file.getCanonicalPath();
            } catch (IOException e) {
            }
            if (canPath == null)
                return null;
            
            // Check to see if going outside of the web application root
            if (!canPath.startsWith(alternateAbsoluteBase)) {
                return null;
            }
            
            // Case sensitivity check
            if (caseSensitive) {
                String fileAbsPath = file.getAbsolutePath();
                if (fileAbsPath.endsWith("."))
                    fileAbsPath = fileAbsPath + "/";
                String absPath = normalize(fileAbsPath);
                if (canPath != null)
                    canPath = normalize(canPath);
                if ((alternateAbsoluteBase.length() < absPath.length()) && (alternateAbsoluteBase.length() < canPath.length())) {
                    absPath = absPath.substring(alternateAbsoluteBase.length() + 1);
                    if ((canPath == null) || (absPath == null))
                        return null;
                    if (absPath.equals(""))
                        absPath = "/";
                    canPath = canPath.substring(alternateAbsoluteBase.length() + 1);
                    if (canPath.equals(""))
                        canPath = "/";
                    if (!canPath.equals(absPath))
                        return null;
                }
            }
            
        } else {
            return null;
        }
        return file;
        
    }
    
}
