package org.jboss.seam.security.management.picketlink;

import org.jboss.solder.properties.Property;

/**
 * Used to map attributes to properties spread across the object model
 * @author baraber
 */
class MappedAttribute {
    /**
     * The property of the IdentityObject class that references the object that
     * contains the attribute property
     */
    private Property<Object> identityProperty;
    /**
     * The property of the mapped object that contains the attribute value
     */
    private Property<Object> attributeProperty;

    public MappedAttribute(Property<Object> identityProperty, Property<Object> attributeProperty) {
        this.identityProperty = identityProperty;
        this.attributeProperty = attributeProperty;
    }

    public Property<Object> getIdentityProperty() {
        return identityProperty;
    }

    public Property<Object> getAttributeProperty() {
        return attributeProperty;
    }
    
}
