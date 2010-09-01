/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.seam.security.external.saml.sp;

import java.util.LinkedList;
import java.util.List;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConstants;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.api.SamlNameId;
import org.jboss.seam.security.external.api.SamlPrincipal;
import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AssertionType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeStatementType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AuthnStatementType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.StatementAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.SubjectConfirmationDataType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.SubjectConfirmationType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlEntityBean;
import org.jboss.seam.security.external.saml.SamlMessageFactory;
import org.jboss.seam.security.external.saml.SamlMessageSender;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.saml.SamlRedirectMessage;
import org.jboss.seam.security.external.saml.SamlServiceType;
import org.jboss.seam.security.external.saml.SamlUtils;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.slf4j.Logger;

/**
 * @author Marcel Kolsteren
 * 
 */
public class SamlSpSingleSignOnService
{
   @Inject
   private Logger log;

   @Inject
   private SamlSpSessions samlSpSessions;

   @Inject
   private Instance<SamlServiceProviderSpi> samlServiceProviderSpi;

   @Inject
   private Instance<SamlEntityBean> samlEntityBean;

   @Inject
   private Dialogue dialogue;

   @Inject
   private SamlMessageSender samlMessageSender;

   @Inject
   private SamlDialogue samlDialogue;

   @Inject
   private SamlMessageFactory samlMessageFactory;

   public void processIDPResponse(HttpServletRequest httpRequest, StatusResponseType statusResponse) throws InvalidRequestException
   {
      SamlExternalIdentityProvider idp = (SamlExternalIdentityProvider) samlDialogue.getExternalProvider();

      StatusType status = statusResponse.getStatus();
      if (status == null)
      {
         throw new InvalidRequestException("Response does not contain a status");
      }

      String statusValue = status.getStatusCode().getValue();
      if (SamlConstants.STATUS_SUCCESS.equals(statusValue) == false)
      {
         samlServiceProviderSpi.get().loginFailed();
      }

      if (!(statusResponse instanceof ResponseType))
      {
         throw new InvalidRequestException("Response does not have type ResponseType");
      }

      ResponseType response = (ResponseType) statusResponse;

      List<Object> assertions = response.getAssertionOrEncryptedAssertion();
      if (assertions.size() == 0)
      {
         throw new RuntimeException("IDP response does not contain assertions");
      }

      SamlSpSession session = createSession(response, idp);
      if (session == null)
      {
         throw new InvalidRequestException("Not possible to login based on the supplied assertions");
      }
      else
      {
         session.setIdentityProvider(idp);
         loginUser(httpRequest, session, statusResponse.getInResponseTo() == null, httpRequest.getParameter(SamlRedirectMessage.QSP_RELAY_STATE));
      }

      dialogue.setFinished(true);
   }

   private SamlSpSession createSession(ResponseType responseType, SamlExternalIdentityProvider idp)
   {
      SamlSpSession session = null;

      for (Object assertion : responseType.getAssertionOrEncryptedAssertion())
      {
         if (assertion instanceof AssertionType)
         {
            SamlSpSession sessionExtractedFromAssertion = handleAssertion((AssertionType) assertion, idp);
            if (session == null)
            {
               session = sessionExtractedFromAssertion;
            }
            else
            {
               log.warn("Multiple authenticated users found in assertions. Using the first one.");
            }
         }
         else
         {
            /* assertion instanceof EncryptedElementType */
            log.warn("Encountered encrypted assertion. Skipping it because decryption is not yet supported.");
         }
      }
      return session;
   }

   private SamlSpSession handleAssertion(AssertionType assertion, SamlExternalIdentityProvider idp)
   {
      if (SamlUtils.hasAssertionExpired(assertion))
      {
         log.warn("Received assertion not processed because it has expired.");
         return null;
      }

      AuthnStatementType authnStatement = extractValidAuthnStatement(assertion);
      if (authnStatement == null)
      {
         log.warn("Received assertion not processed because it doesn't contain a valid authnStatement.");
         return null;
      }

      NameIDType nameId = validateSubjectAndExtractNameID(assertion);
      if (nameId == null)
      {
         log.warn("Received assertion not processed because it doesn't contain a valid subject.");
         return null;
      }

      SamlPrincipal principal = new SamlPrincipal();
      principal.setAssertion(assertion);
      principal.setNameId(new SamlNameId(nameId.getValue(), nameId.getFormat(), nameId.getNameQualifier()));
      SamlSpSession session = new SamlSpSession();
      session.setSessionIndex(authnStatement.getSessionIndex());
      session.setPrincipal(principal);
      session.setIdentityProvider(idp);

      for (StatementAbstractType statement : assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement())
      {
         if (statement instanceof AttributeStatementType)
         {
            AttributeStatementType attributeStatement = (AttributeStatementType) statement;
            List<AttributeType> attributes = new LinkedList<AttributeType>();
            for (Object object : attributeStatement.getAttributeOrEncryptedAttribute())
            {
               if (object instanceof AttributeType)
               {
                  attributes.add((AttributeType) object);
               }
               else
               {
                  log.warn("Encrypted attributes are not supported. Ignoring the attribute.");
               }
            }
            principal.setAttributes(attributes);
         }
      }

      return session;
   }

   private AuthnStatementType extractValidAuthnStatement(AssertionType assertion)
   {
      for (StatementAbstractType statement : assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement())
      {
         if (statement instanceof AuthnStatementType)
         {
            AuthnStatementType authnStatement = (AuthnStatementType) statement;
            return authnStatement;
         }
      }

      return null;
   }

   private NameIDType validateSubjectAndExtractNameID(AssertionType assertion)
   {
      NameIDType nameId = null;
      boolean validConfirmationFound = false;

      for (JAXBElement<?> contentElement : assertion.getSubject().getContent())
      {
         if (contentElement.getValue() instanceof NameIDType)
         {
            nameId = (NameIDType) contentElement.getValue();
         }
         if (contentElement.getValue() instanceof SubjectConfirmationType)
         {
            SubjectConfirmationType confirmation = (SubjectConfirmationType) contentElement.getValue();
            if (confirmation.getMethod().equals(SamlConstants.CONFIRMATION_METHOD_BEARER))
            {
               SubjectConfirmationDataType confirmationData = confirmation.getSubjectConfirmationData();

               boolean validRecipient = confirmationData.getRecipient().equals(samlEntityBean.get().getServiceURL(SamlServiceType.SAML_ASSERTION_CONSUMER_SERVICE));

               boolean notTooLate = confirmationData.getNotOnOrAfter().compare(SamlUtils.getXMLGregorianCalendarNow()) == DatatypeConstants.GREATER;

               boolean validInResponseTo = confirmationData.getInResponseTo() == null || confirmationData.getInResponseTo().equals(dialogue.getDialogueId());

               if (validRecipient && notTooLate && validInResponseTo)
               {
                  validConfirmationFound = true;
               }
               else
               {
                  log.debug("Validation of assertion failed: validRecipient: {}; notTootLate: {}; validInResponseTo: {}", new Object[] { validRecipient, notTooLate, validInResponseTo });
               }
            }
         }
      }

      if (validConfirmationFound)
      {
         return nameId;
      }
      else
      {
         return null;
      }
   }

   private void loginUser(HttpServletRequest httpRequest, SamlSpSession session, boolean unsolicited, String relayState)
   {
      samlSpSessions.addSession(session);

      if (unsolicited)
      {
         samlServiceProviderSpi.get().loggedIn(session, relayState);
      }
      else
      {
         samlServiceProviderSpi.get().loginSucceeded(session);
      }
   }

   public void sendAuthenticationRequestToIDP(SamlExternalIdentityProvider idp)
   {
      AuthnRequestType authnRequest = samlMessageFactory.createAuthnRequest();

      samlDialogue.setExternalProvider(idp);

      samlMessageSender.sendRequest(idp, SamlProfile.SINGLE_SIGN_ON, authnRequest);
   }
}
