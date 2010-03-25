package org.jboss.seam.security.examples.seamspace;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.jboss.seam.security.annotations.permission.PermissionAction;
import org.jboss.seam.security.annotations.permission.PermissionDiscriminator;
import org.jboss.seam.security.annotations.permission.PermissionRole;
import org.jboss.seam.security.annotations.permission.PermissionTarget;
import org.jboss.seam.security.annotations.permission.PermissionUser;

@Entity
public class AccountPermission implements Serializable
{
   private static final long serialVersionUID = -5628863031792429938L;
   
   private Integer permissionId;
   private String recipient;
   private String target;
   private String action;
   private String discriminator;
   
   @Id @GeneratedValue
   public Integer getPermissionId()
   {
      return permissionId;
   }
   
   public void setPermissionId(Integer permissionId)
   {
      this.permissionId = permissionId;
   }
   
   @PermissionUser 
   @PermissionRole
   public String getRecipient()
   {
      return recipient;
   }
   
   public void setRecipient(String recipient)
   {
      this.recipient = recipient;
   }
   
   @PermissionTarget
   public String getTarget()
   {
      return target;
   }
   
   public void setTarget(String target)
   {
      this.target = target;
   }
   
   @PermissionAction
   public String getAction()
   {
      return action;
   }
   
   public void setAction(String action)
   {
      this.action = action;
   }
   
   @PermissionDiscriminator
   public String getDiscriminator()
   {
      return discriminator;
   }
   
   public void setDiscriminator(String discriminator)
   {
      this.discriminator = discriminator;
   }
}
