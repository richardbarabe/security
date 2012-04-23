package org.jboss.seam.security.management.picketlink;

import java.util.HashMap;
import java.util.Map;
import org.jboss.seam.security.management.IdentityObjectRelationshipTypeImpl;
import org.jboss.seam.security.management.IdentityObjectTypeImpl;
import org.jboss.solder.properties.Property;
import org.picketlink.idm.impl.types.SimpleIdentityObject;
import org.picketlink.idm.spi.model.IdentityObject;
import org.picketlink.idm.spi.model.IdentityObjectRelationshipType;
import org.picketlink.idm.spi.model.IdentityObjectType;

/**
 *
 * @author baraber
 */
public class EntityToSpiConverter {
    private static final String IDENTITY_TYPE_CACHE_PREFIX = "identity_type:";
    private static final String RELATIONSHIP_TYPE_CACHE_PREFIX = "relationship_type:";
    private Map<Object, Object> cache = new HashMap<Object, Object>();
    
    private Class<?> identityClass;
    
    private Property<?> identityIdProperty;
    private Property<?> identityNameProperty;
    private Property<?> identityTypeProperty;
    private Property<?> identityTypeNameProperty;
    private Property<?> relationshipTypeNameProperty;

    public EntityToSpiConverter() {
    }

    public IdentityObject convertToIdentityObject(Object entity) {
        if (!identityClass.isAssignableFrom(entity.getClass())) {
            throw new IllegalArgumentException("Invalid identity entity");
        }
        if (cache.containsKey(entity)) {
            return (IdentityObject) cache.get(entity);
        } else {
            IdentityObject obj = new SimpleIdentityObject(identityNameProperty.getValue(entity).toString(), identityIdProperty.getValue(entity).toString(), convertToIdentityObjectType(identityTypeProperty.getValue(entity)));
            cache.put(entity, obj);
            return obj;
        }
    }

    public IdentityObjectType convertToIdentityObjectType(Object value) {
        if (value instanceof String) {
            String key = IDENTITY_TYPE_CACHE_PREFIX + (String) value;
            if (cache.containsKey(key)) {
                return (IdentityObjectType) cache.get(key);
            }
            IdentityObjectType type = new IdentityObjectTypeImpl((String) value);
            cache.put(key, type);
            return type;
        } else {
            if (cache.containsKey(value)) {
                return (IdentityObjectType) cache.get(value);
            }
            IdentityObjectType type = new IdentityObjectTypeImpl((String) identityTypeNameProperty.getValue(value));
            cache.put(value, type);
            return type;
        }
    }

    public IdentityObjectRelationshipType convertToRelationshipType(Object value) {
        if (value instanceof String) {
            String key = RELATIONSHIP_TYPE_CACHE_PREFIX + (String) value;
            if (cache.containsKey(key)) {
                return (IdentityObjectRelationshipType) cache.get(key);
            }
            IdentityObjectRelationshipType type = new IdentityObjectRelationshipTypeImpl((String) value);
            cache.put(key, type);
            return type;
        } else {
            if (cache.containsKey(value)) {
                return (IdentityObjectRelationshipType) cache.get(value);
            }
            IdentityObjectRelationshipType type = new IdentityObjectRelationshipTypeImpl((String) relationshipTypeNameProperty.getValue(value));
            cache.put(value, type);
            return type;
        }
    }

    public Property<?> getIdentityIdProperty() {
        return identityIdProperty;
    }

    public void setIdentityIdProperty(Property<?> identityIdProperty) {
        this.identityIdProperty = identityIdProperty;
    }

    public Property<?> getIdentityNameProperty() {
        return identityNameProperty;
    }

    public void setIdentityNameProperty(Property<?> identityNameProperty) {
        this.identityNameProperty = identityNameProperty;
    }

    public Property<?> getIdentityTypeNameProperty() {
        return identityTypeNameProperty;
    }

    public void setIdentityTypeNameProperty(Property<?> identityTypeNameProperty) {
        this.identityTypeNameProperty = identityTypeNameProperty;
    }

    public Property<?> getIdentityTypeProperty() {
        return identityTypeProperty;
    }

    public void setIdentityTypeProperty(Property<?> identityTypeProperty) {
        this.identityTypeProperty = identityTypeProperty;
    }

    public Property<?> getRelationshipTypeNameProperty() {
        return relationshipTypeNameProperty;
    }

    public void setRelationshipTypeNameProperty(Property<?> relationshipTypeNameProperty) {
        this.relationshipTypeNameProperty = relationshipTypeNameProperty;
    }

    public Class<?> getIdentityClass() {
        return identityClass;
    }

    public void setIdentityClass(Class<?> identityClass) {
        this.identityClass = identityClass;
    }

    public void setModelProperties(Map<String, Property<Object>> modelProperties) {
        setIdentityIdProperty(modelProperties.get(JpaIdentityStoreConfiguration.PROPERTY_IDENTITY_ID));
        setIdentityNameProperty(modelProperties.get(JpaIdentityStoreConfiguration.PROPERTY_IDENTITY_NAME));
        setIdentityTypeProperty(modelProperties.get(JpaIdentityStoreConfiguration.PROPERTY_IDENTITY_TYPE));
        setIdentityTypeNameProperty(modelProperties.get(JpaIdentityStoreConfiguration.PROPERTY_IDENTITY_TYPE_NAME));
        setRelationshipTypeNameProperty(modelProperties.get(JpaIdentityStoreConfiguration.PROPERTY_RELATIONSHIP_TYPE_NAME));
    }
    
}
