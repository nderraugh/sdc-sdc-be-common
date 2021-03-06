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

import org.onap.sdc.security.logging.api.ILogConfiguration;
import org.onap.sdc.security.logging.api.ILogFieldsHandler;
import org.onap.sdc.security.logging.enums.LogLevel;
import org.onap.sdc.security.logging.enums.LogMarkers;
import org.onap.sdc.security.logging.enums.LoggerSupportabilityActions;
import org.onap.sdc.security.logging.enums.StatusCode;
import org.slf4j.Logger;
import org.slf4j.MarkerFactory;

import java.util.*;

public class LoggerSupportability extends LoggerBase {

  public LoggerSupportability(ILogFieldsHandler ecompLogFieldsHandler, Logger logger) {
    super(ecompLogFieldsHandler, MarkerFactory.getMarker(LogMarkers.SUPPORTABILITY_MARKER.text()),
        logger);
  }

  public static LoggerSupportability getLogger(String className) {
    return LoggerFactory.getMdcLogger(LoggerSupportability.class,
        org.slf4j.LoggerFactory.getLogger(className));
  }


  public void log(LoggerSupportabilityActions action, Map<String,String> componentMetaData, StatusCode statusCode, String message, Object...params) {
    fillFieldsBeforeLogging(action,componentMetaData,statusCode);
    super.log(LogLevel.INFO,message, params);
  }

  public void log(LoggerSupportabilityActions action, StatusCode statusCode, String message, Object...params) {
    log(action, null, statusCode, message, params);
  }

  private static ArrayList<String> mandatoryFields = new ArrayList<>(Arrays.asList(
      ILogConfiguration.MDC_SUPPORTABLITY_ACTION,
      ILogConfiguration.MDC_SUPPORTABLITY_CSAR_UUID,
      ILogConfiguration.MDC_SUPPORTABLITY_CSAR_VERSION,
      ILogConfiguration.MDC_SUPPORTABLITY_COMPONENT_NAME,
      ILogConfiguration.MDC_SUPPORTABLITY_COMPONENT_UUID,
      ILogConfiguration.MDC_SUPPORTABLITY_COMPONENT_VERSION,
      ILogConfiguration.MDC_SUPPORTABLITY_STATUS_CODE));

  private void fillFieldsBeforeLogging(LoggerSupportabilityActions action, Map<String,String> componentMetaData, StatusCode statusCode) {
    clear();
    if (componentMetaData!=null){
      ecompLogFieldsHandler.setSupportablityCsarUUID(componentMetaData.get(ILogConfiguration.MDC_SUPPORTABLITY_CSAR_UUID));
      ecompLogFieldsHandler.setSupportablityCsarVersion(componentMetaData.get(ILogConfiguration.MDC_SUPPORTABLITY_CSAR_VERSION));
      ecompLogFieldsHandler.setSupportablityComponentName(componentMetaData.get(ILogConfiguration.MDC_SUPPORTABLITY_COMPONENT_NAME));
      ecompLogFieldsHandler.setSupportablityComponentUUID(componentMetaData.get(ILogConfiguration.MDC_SUPPORTABLITY_COMPONENT_UUID));
      ecompLogFieldsHandler.setSupportablityComponentVersion(componentMetaData.get(ILogConfiguration.MDC_SUPPORTABLITY_COMPONENT_VERSION));
    }
    ecompLogFieldsHandler.setSupportablityAction(action.getName());
    ecompLogFieldsHandler.setSupportablityStatusCode(statusCode.getStatusCodeEnum());
    }

  @Override
  public LoggerSupportability clear(){
    LogFieldsMdcHandler.getInstance().removeSupportablityAction();
    LogFieldsMdcHandler.getInstance().removeSupportablityCsarUUID();
    LogFieldsMdcHandler.getInstance().removeSupportablityCsarVersion();
    LogFieldsMdcHandler.getInstance().removeSupportablityComponentName();
    LogFieldsMdcHandler.getInstance().removeSupportablityComponentUUID();
    LogFieldsMdcHandler.getInstance().removeSupportablityComponentVersion();
    LogFieldsMdcHandler.getInstance().removeSupportablityStatusCode();
    return this;
  }


  @Override
  public List<String> getMandatoryFields() {
    return Collections.unmodifiableList(mandatoryFields);
  }

  @Override
  public LoggerSupportability startTimer() {
    return this;
  }

}
