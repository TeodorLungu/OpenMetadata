package org.openmetadata.service.secrets;
/*
 *  Copyright 2021 Collate
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import java.io.IOException;
import org.openmetadata.schema.security.secrets.SecretsManagerProvider;

public abstract class GoogleBasedSecretsManager extends ExternalSecretsManager {

    /**
     * GOOGLE_APPLICATION_CREDENTIALS=<path to google project json file > If you are using IntelliJ idea, Edit the Project
     * configuration and add the Environment variable
     */
    public static final String PROJECT_ID = "PROJECT_ID";

    protected GoogleBasedSecretsManager(SecretsManagerProvider gsmProvider, String clusterPrefix) throws IOException {
        super(gsmProvider, clusterPrefix, 100);
        // initialize the secret client depending on the SecretsManagerConfiguration passed
        initClient();
        initProjectIDAndProjectName(PROJECT_ID);
    }

    abstract void initClient() throws IOException;

    abstract void initProjectIDAndProjectName(String projectID) throws IOException;
}
