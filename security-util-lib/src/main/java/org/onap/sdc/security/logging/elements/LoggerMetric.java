/*-
 * ============LICENSE_START=======================================================
 * SDC
 * ================================================================================
 * Copyright (C) 2017 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
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
 * ============LICENSE_END=========================================================
 */

package org.onap.sdc.security.logging.elements;

import org.onap.sdc.security.logging.api.ILogFieldsHandler;
import org.onap.sdc.security.logging.enums.LogLevel;
import org.onap.sdc.security.logging.enums.LogMarkers;
import org.onap.sdc.security.logging.enums.Severity;
import org.slf4j.Logger;
import org.slf4j.MarkerFactory;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.onap.logging.ref.slf4j.ONAPLogConstants.MDCs.*;
import static org.onap.sdc.security.logging.api.ILogConfiguration.*;


public class LoggerMetric extends LoggerBase {
    private static ArrayList<String> mandatoryFields = new ArrayList<>(Arrays.asList(
            INVOKE_TIMESTAMP,
            MDC_END_TIMESTAMP,
            REQUEST_ID,
            SERVICE_NAME,
            PARTNER_NAME,
            RESPONSE_CODE,
            MDC_SERVICE_INSTANCE_ID,
            RESPONSE_DESCRIPTION,
            MDC_ELAPSED_TIME,
            TARGET_ENTITY,
            MDC_SERVER_IP_ADDRESS,
            SERVER_FQDN));

    private static ArrayList<String> optionalFields = new ArrayList<>(Arrays.asList(
            MDC_TARGET_VIRTUAL_ENTITY,
            TARGET_ENTITY,
            TARGET_SERVICE_NAME,
            RESPONSE_STATUS_CODE,
            INSTANCE_UUID,
            RESPONSE_SEVERITY,
            MDC_REMOTE_HOST,
            CLIENT_IP_ADDRESS,
            MDC_CLASS_NAME,
            MDC_PROCESS_KEY,
            MDC_OPT_FIELD1,
            MDC_OPT_FIELD2,
            MDC_OPT_FIELD3,
            MDC_OPT_FIELD4));

    LoggerMetric(ILogFieldsHandler ecompMdcWrapper, Logger logger) {
        super(ecompMdcWrapper, MarkerFactory.getMarker(LogMarkers.METRIC_MARKER.text()), logger);
        //put the remote host and FQDN values from another thread if they are set
        ecompMdcWrapper.setServerIPAddressInternally();
        ecompMdcWrapper.setServerFQDNInternally();
    }

    public void log(Response.StatusType statusInfo,
                    String className,
                    LogLevel logLevel,
                    Severity securityLevel,
                    String message) {
        log(statusInfo,className, logLevel, securityLevel, message);
    }

    @Override
    public void log(LogLevel logLevel, String message) {
        setKeyRequestIdIfNotSetYet();
        log(logLevel, message, (Object) null);
    }

    @Override
    public LoggerMetric startTimer() {
        clear();
        ecompLogFieldsHandler.startMetricTimer();
        return this;
    }

    public LoggerMetric stopTimer() {
        ecompLogFieldsHandler.stopMetricTimer();
        return this;
    }

    @Override
    public LoggerMetric setKeyRequestId(String keyRequestId) {
        return (LoggerMetric) super.setKeyRequestId(keyRequestId);
    }

    @Override
    public List<String> getMandatoryFields() {
        return mandatoryFields;
    }

    @Override
    public LoggerMetric clear() {
        ecompLogFieldsHandler.removeTargetEntity();
        ecompLogFieldsHandler.removeTargetServiceName();
        ecompLogFieldsHandler.removeResponseCode();
        ecompLogFieldsHandler.removeResponseDesc();
        ecompLogFieldsHandler.removeStatusCode();
        return this;
    }

    // automatic parameter this is optional
    public LoggerMetric setAutoServerFQDN(String serverFQDN) {
        ecompLogFieldsHandler.setServerFQDN(serverFQDN);
        return this;
    }

    // automatic parameter this is optional
    public LoggerMetric setAutoServerIPAddress(String serverIPAddress) {
        ecompLogFieldsHandler.setServerIPAddress(serverIPAddress);
        return this;
    }

    public LoggerMetric setInstanceUUID(String instanceUUID) {
        ecompLogFieldsHandler.setInstanceUUID(instanceUUID);
        return this;
    }

    // log optional parameter
    public LoggerMetric setOptProcessKey(String processKey) {
        ecompLogFieldsHandler.setProcessKey(processKey);
        return this;
    }

    // log optional parameter
    public LoggerMetric setOptAlertSeverity(Severity alertSeverity) {
        ecompLogFieldsHandler.setAlertSeverity(alertSeverity);
        return this;
    }

    // log optional parameter
    public LoggerMetric setOptCustomField1(String customField1) {
        ecompLogFieldsHandler.setOptCustomField1(customField1);
        return this;
    }

    // log optional parameter
    public LoggerMetric setOptCustomField2(String customField2) {
        ecompLogFieldsHandler.setOptCustomField2(customField2);
        return this;
    }

    // log optional parameter
    public LoggerMetric setOptCustomField3(String customField3) {
        ecompLogFieldsHandler.setOptCustomField3(customField3);
        return this;
    }

    // log optional parameter
    public LoggerMetric setOptCustomField4(String customField4) {
        ecompLogFieldsHandler.setOptCustomField4(customField4);
        return this;
    }

    public LoggerMetric setRemoteHost(String remoteHost) {
        ecompLogFieldsHandler.setRemoteHost(remoteHost);
        return this;
    }

    public LoggerMetric setServiceName(String serviceName) {
        ecompLogFieldsHandler.setServiceName(serviceName);
        return this;
    }

    public LoggerMetric setStatusCode(String statusCode) {
        ecompLogFieldsHandler.setStatusCode(statusCode);
        return this;
    }

    public LoggerMetric setPartnerName(String partnerName) {
        ecompLogFieldsHandler.setPartnerName(partnerName);
        return this;
    }

    public LoggerMetric setResponseCode(int responseCode) {
        ecompLogFieldsHandler.setResponseCode(responseCode);
        return this;
    }

    public LoggerMetric setResponseDesc(String responseDesc) {
        ecompLogFieldsHandler.setResponseDesc(responseDesc);
        return this;
    }

    public LoggerMetric setOptServiceInstanceId(String serviceInstanceId) {
        ecompLogFieldsHandler.setServiceInstanceId(serviceInstanceId);
        return this;
    }

    public LoggerMetric setOptClassName(String className) {
        ecompLogFieldsHandler.setClassName(className);
        return this;
    }

    public LoggerMetric setTargetEntity(String targetEntity) {
        ecompLogFieldsHandler.setTargetEntity(targetEntity);
        return this;
    }

    public LoggerMetric setTargetServiceName(String targetServiceName) {
        ecompLogFieldsHandler.setTargetServiceName(targetServiceName);
        return this;
    }

    public LoggerMetric setTargetVirtualEntity(String targetVirtualEntity) {
        ecompLogFieldsHandler.setTargetVirtualEntity(targetVirtualEntity);
        return this;
    }




}
