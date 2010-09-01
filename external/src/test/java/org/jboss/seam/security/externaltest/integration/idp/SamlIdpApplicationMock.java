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
package org.jboss.seam.security.externaltest.integration.idp;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.api.SamlMultiUserIdentityProviderApi;
import org.jboss.seam.security.external.api.SamlNameId;
import org.jboss.seam.security.external.dialogues.DialogueManager;
import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.idp.SamlIdpSession;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;
import org.slf4j.Logger;

@ApplicationScoped
public class SamlIdpApplicationMock implements SamlIdentityProviderSpi
{
   @Inject
   private ResponseHolder responseHolder;

   @Inject
   private DialogueManager dialogueManager;

   @Inject
   private Dialogue dialogue;

   @Inject
   private Instance<SamlMultiUserIdentityProviderApi> idpApi;

   private String dialogueId;

   @Inject
   private Logger log;

   public void authenticate()
   {
      dialogueId = dialogue.getDialogueId();
      try
      {
         responseHolder.getResponse().getWriter().print("Please login");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void handleLogin(String userName)
   {
      SamlIdpSession session = idpApi.get().localLogin(new SamlNameId(userName, null, null), null);
      dialogueManager.attachDialogue(dialogueId);
      idpApi.get().authenticationSucceeded(session);
      dialogueManager.detachDialogue();
   }

   public int getNumberOfSessions()
   {
      return idpApi.get().getSessions().size();
   }

   public void singleLogoutFailed()
   {
      try
      {
         responseHolder.getResponse().getWriter().print("Single logout failed");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   public void singleLogoutSucceeded()
   {
      try
      {
         responseHolder.getResponse().getWriter().print("Single logout succeeded");
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }

   @Dialogued
   public void handleSingleLogout()
   {
      idpApi.get().globalLogout(idpApi.get().getSessions().iterator().next());
   }

   public void loggedOut(SamlIdpSession session)
   {
      log.info("User " + session.getPrincipal().getNameId().getValue() + " has been logged out.");
   }
}
