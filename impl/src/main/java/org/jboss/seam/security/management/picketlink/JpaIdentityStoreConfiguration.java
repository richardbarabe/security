package org.jboss.seam.security.management.picketlink;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.PostConstruct;
import javax.annotation.PostConstruct;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.persistence.Entity;
import javax.persistence.Id;

import org.jboss.seam.security.annotations.management.IdentityEntity;
import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;
import org.jboss.solder.properties.Property;
import org.jboss.solder.properties.query.AnnotatedPropertyCriteria;
import org.jboss.solder.properties.query.NamedPropertyCriteria;
import org.jboss.solder.properties.query.PropertyCriteria;
import org.jboss.solder.properties.query.PropertyQueries;
import org.jboss.solder.properties.query.TypedPropertyCriteria;
import org.picketlink.idm.common.exception.IdentityException;
import org.picketlink.idm.impl.configuration.metadata.IdentityStoreConfigurationMetaDataImpl;

/**
 * A convenience class for setting JpaIdentityStore configuration options.
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class JpaIdentityStoreConfiguration extends IdentityStoreConfiguration implements Extension {

    private Class<?> identityClass;
    private Class<?> credentialClass;
    private Class<?> relationshipClass;
    private Class<?> roleTypeClass;
    private Class<?> attributeClass;

    public <X> void processAnnotatedType(@Observes ProcessAnnotatedType<X> event,
        final BeanManager beanManager) {
        if (event.getAnnotatedType().isAnnotationPresent(Entity.class)) {
            AnnotatedType<X> type = event.getAnnotatedType();

            if (type.isAnnotationPresent(IdentityEntity.class)) {
                IdentityEntity a = type.getAnnotation(IdentityEntity.class);

                switch (a.value()) {
                    case IDENTITY_OBJECT:
                        identityClass = type.getJavaClass();
                        break;
                    case IDENTITY_CREDENTIAL:
                        credentialClass = type.getJavaClass();
                        break;
                    case IDENTITY_RELATIONSHIP:
                        relationshipClass = type.getJavaClass();
                        break;
                    case IDENTITY_ATTRIBUTE:
                        attributeClass = type.getJavaClass();
                        break;
                    case IDENTITY_ROLE_NAME:
                        roleTypeClass = type.getJavaClass();
                        break;
                }
            }
        }
    }

    @Override
    public String getId() {
        return (super.getId() == null) ? "jpa" : super.getId();
    }

    /**
     * If the identityStoreClass hasn't been set, then return JpaIdentityStore by default.
     */
    @Override
    public Class<?> getIdentityStoreClass() {
        return (super.getIdentityStoreClass() == null) ? JpaIdentityStore.class : super.getIdentityStoreClass();
    }

    public Class<?> getIdentityClass() {
        return identityClass;
    }

    public void setIdentityClass(Class<?> identityClass) {
        this.identityClass = identityClass;
    }

    public Class<?> getCredentialClass() {
        return credentialClass;
    }

    public void setCredentialClass(Class<?> credentialClass) {
        this.credentialClass = credentialClass;
    }

    public Class<?> getRelationshipClass() {
        return relationshipClass;
    }

    public void setRelationshipClass(Class<?> relationshipClass) {
        this.relationshipClass = relationshipClass;
    }

    public Class<?> getRoleTypeClass() {
        return roleTypeClass;
    }

    public void setRoleTypeClass(Class<?> roleTypeClass) {
        this.roleTypeClass = roleTypeClass;
    }

    public Class<?> getAttributeClass() {
        return attributeClass;
    }

    public void setAttributeClass(Class<?> attributeClass) {
        this.attributeClass = attributeClass;
    }

    public void doConfigure(IdentityStoreConfigurationMetaDataImpl store) {
        Map<String, List<String>> options = new HashMap<String, List<String>>();

        if (identityClass != null) {
            options.put(JpaIdentityStore.OPTION_IDENTITY_CLASS_NAME, createOptionList(identityClass.getName()));
        }

        if (credentialClass != null) {
            options.put(JpaIdentityStore.OPTION_CREDENTIAL_CLASS_NAME, createOptionList(credentialClass.getName()));
        }

        if (relationshipClass != null) {
            options.put(JpaIdentityStore.OPTION_RELATIONSHIP_CLASS_NAME, createOptionList(relationshipClass.getName()));
        }

        if (roleTypeClass != null) {
            options.put(JpaIdentityStore.OPTION_ROLE_TYPE_CLASS_NAME, createOptionList(roleTypeClass.getName()));
        }

        if (attributeClass != null) {
            options.put(JpaIdentityStore.OPTION_ATTRIBUTE_CLASS_NAME, createOptionList(attributeClass.getName()));
        }

        store.setOptions(options);
        try {

            configureIdentityId();
            configureIdentityName();
            configureIdentityType();

            configureCredentials();
            configureRelationships();
            configureAttributes();

            if (namedRelationshipsSupported) {
                configureRoleTypeName();
            }
        } catch (IdentityException ex) {
            Logger.getLogger(JpaIdentityStoreConfiguration.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public boolean isConfigured() {
        return identityClass != null;
    }

    private List<String> createOptionList(String... values) {
        List<String> vals = new ArrayList<String>();
        for (String v : values) {
            vals.add(v);
        }
        return vals;
    }
//***************************************************************************************************
//***************************************************************************************************
    private boolean namedRelationshipsSupported = false;
    private Map<String, Property<Object>> identityModelProperties = new HashMap<String, Property<Object>>();
    private Map<String, MappedAttribute> attributeProperties = new HashMap<String, MappedAttribute>();
    // Property keys
    static final String PROPERTY_IDENTITY_ID = "IDENTITY_ID";
    static final String PROPERTY_IDENTITY_NAME = "IDENTITY_NAME";
    static final String PROPERTY_IDENTITY_TYPE = "IDENTITY_TYPE";
    static final String PROPERTY_IDENTITY_TYPE_NAME = "IDENTITY_TYPE_NAME";
    static final String PROPERTY_CREDENTIAL_VALUE = "CREDENTIAL_VALUE";
    static final String PROPERTY_CREDENTIAL_IDENTITY = "CREDENTIAL_IDENTITY";
    static final String PROPERTY_CREDENTIAL_TYPE = "CREDENTIAL_TYPE";
    static final String PROPERTY_CREDENTIAL_TYPE_NAME = "CREDENTIAL_TYPE_NAME";
    static final String PROPERTY_RELATIONSHIP_FROM = "RELATIONSHIP_FROM";
    static final String PROPERTY_RELATIONSHIP_TO = "RELATIONSHIP_TO";
    static final String PROPERTY_RELATIONSHIP_TYPE = "RELATIONSHIP_TYPE";
    static final String PROPERTY_RELATIONSHIP_NAME = "RELATIONSHIP_NAME";
    static final String PROPERTY_RELATIONSHIP_TYPE_NAME = "RELATIONSHIP_TYPE_NAME";
    static final String PROPERTY_ATTRIBUTE_NAME = "ATTRIBUTE_NAME";
    static final String PROPERTY_ATTRIBUTE_VALUE = "ATTRIBUTE_VALUE";
    static final String PROPERTY_ATTRIBUTE_IDENTITY = "ATTRIBUTE_IDENTITY";
    static final String PROPERTY_ATTRIBUTE_TYPE = "ATTRIBUTE_TYPE";
    static final String PROPERTY_ROLE_TYPE_NAME = "RELATIONSHIP_NAME_NAME";

    private class IdentityPropertyTypeCriteria implements PropertyCriteria {

        private PropertyType pt;

        public IdentityPropertyTypeCriteria(PropertyType pt) {
            this.pt = pt;
        }

        public boolean fieldMatches(Field f) {
            return f.isAnnotationPresent(IdentityProperty.class)
                && f.getAnnotation(IdentityProperty.class).value().equals(pt);
        }

        public boolean methodMatches(Method m) {
            return m.isAnnotationPresent(IdentityProperty.class)
                && m.getAnnotation(IdentityProperty.class).value().equals(pt);
        }
    }

    @Produces
    public EntityToSpiConverter getEntityToSpiConverter() {
        EntityToSpiConverter converter = new EntityToSpiConverter();
        converter.setIdentityClass(identityClass);
        converter.setIdentityIdProperty(identityModelProperties.get(PROPERTY_IDENTITY_ID));
        converter.setIdentityNameProperty(identityModelProperties.get(PROPERTY_IDENTITY_NAME));
        converter.setIdentityTypeProperty(identityModelProperties.get(PROPERTY_IDENTITY_TYPE));
        converter.setIdentityTypeNameProperty(identityModelProperties.get(PROPERTY_IDENTITY_TYPE));
        converter.setRelationshipTypeNameProperty(identityModelProperties.get(PROPERTY_RELATIONSHIP_TYPE_NAME));
        return converter;
    }

    @PostConstruct
    public void init() throws IdentityException {
//        String clsName = configurationContext.getStoreConfigurationMetaData()
//                .getOptionSingleValue(OPTION_IDENTITY_CLASS_NAME);
//
//        if (clsName == null) {
//            throw new IdentityException("Error bootstrapping JpaIdentityStore - identity entity class cannot be null");
//        }
//
//        try {
//            identityClass = Reflections.classForName(clsName);
//        } catch (ClassNotFoundException e) {
//            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid identity entity class: " + clsName);
//        }
//
//        if (identityClass == null) {
//            throw new IdentityException(
//                    "Error initializing JpaIdentityStore - identityClass not set");
//        }
//
//        clsName = configurationContext.getStoreConfigurationMetaData()
//                .getOptionSingleValue(OPTION_CREDENTIAL_CLASS_NAME);
//
//        if (clsName != null) {
//            try {
//                credentialClass = Class.forName(clsName);
//            } catch (ClassNotFoundException e) {
//                throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid credential entity class: " + clsName);
//            }
//        }
//
//        clsName = configurationContext.getStoreConfigurationMetaData()
//                .getOptionSingleValue(OPTION_RELATIONSHIP_CLASS_NAME);
//
//        try {
//            relationshipClass = Class.forName(clsName);
//        } catch (ClassNotFoundException e) {
//            throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid relationship entity class: " + clsName);
//        }
//
//        clsName = configurationContext.getStoreConfigurationMetaData()
//                .getOptionSingleValue(OPTION_ROLE_TYPE_CLASS_NAME);
//
//        if (clsName != null) {
//            try {
//                roleTypeClass = Class.forName(clsName);
//                namedRelationshipsSupported = true;
//            } catch (ClassNotFoundException e) {
//                throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid role type entity class: " + clsName);
//            }
//        }
//
//        clsName = configurationContext.getStoreConfigurationMetaData()
//                .getOptionSingleValue(OPTION_ATTRIBUTE_CLASS_NAME);
//        if (clsName != null) {
//            try {
//                attributeClass = Class.forName(clsName);
//            } catch (ClassNotFoundException e) {
//                throw new IdentityException("Error bootstrapping JpaIdentityStore - invalid attribute entity class: " + clsName);
//            }
//        }
    }

    protected void configureIdentityId() throws IdentityException {
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass).addCriteria(new AnnotatedPropertyCriteria(Id.class)).getResultList();

        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_IDENTITY_ID, props.get(0));
        } else {
            throw new IdentityException("Error initializing JpaIdentityStore - no Identity ID found.");
        }
    }

    protected void configureIdentityName() throws IdentityException {
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.NAME)).getResultList();

        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                "Ambiguous identity name property in identity class " + identityClass.getName());
        } else {
            Property<Object> p = findNamedProperty(identityClass, "username", "userName", "name");
            if (p != null) {
                identityModelProperties.put(PROPERTY_IDENTITY_NAME, p);
            } else {
                // Last resort - check whether the entity class exposes a single String property
                // if so, let's assume it's the identity name
                props = PropertyQueries.createQuery(identityClass).addCriteria(new TypedPropertyCriteria(String.class)).getResultList();
                if (props.size() == 1) {
                    identityModelProperties.put(PROPERTY_IDENTITY_NAME, props.get(0));
                }
            }
        }

        if (!identityModelProperties.containsKey(PROPERTY_IDENTITY_NAME)) {
            throw new IdentityException("Error initializing JpaIdentityStore - no valid identity name property found.");
        }
    }

    protected void configureIdentityType() throws IdentityException {
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.TYPE)).getResultList();

        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                "Ambiguous identity type property in identity class " + identityClass.getName());
        } else {
            Property<Object> p = findNamedProperty(identityClass, "identityObjectType",
                "identityType", "identityObjectTypeName", "identityTypeName",
                "typeName", "discriminator", "accountType", "userType", "type");
            if (p != null) {
                identityModelProperties.put(PROPERTY_IDENTITY_TYPE, props.get(0));
            } else {
                // Last resort - let's check all properties, and try to find one
                // with an entity type that has "type" in its name
                props = PropertyQueries.createQuery(identityClass).getResultList();
                search:
                for (Property<Object> typeProp : props) {
                    if (typeProp.getJavaClass().isAnnotationPresent(Entity.class)
                        && (typeProp.getJavaClass().getSimpleName().contains("type")
                        || typeProp.getJavaClass().getSimpleName().contains("Type"))) {
                        // we have a potential match, let's check if this entity has a name property
                        Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                            "identityObjectTypeName", "identityTypeName", "typeName", "name");
                        if (nameProp != null) {
                            identityModelProperties.put(PROPERTY_IDENTITY_TYPE, typeProp);
                            identityModelProperties.put(PROPERTY_IDENTITY_TYPE_NAME, nameProp);
                            break search;
                        }
                    }
                }
            }
        }

        Property<?> typeProp = identityModelProperties.get(PROPERTY_IDENTITY_TYPE);

        if (typeProp == null) {
            throw new IdentityException("Error initializing JpaIdentityStore - no valid identity type property found.");
        }

        if (!String.class.equals(typeProp.getJavaClass())
            && !identityModelProperties.containsKey(PROPERTY_IDENTITY_TYPE_NAME)) {
            // We're not dealing with a simple type name - validate the lookup type
            Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                "identityObjectTypeName", "identityTypeName", "typeName", "name");
            if (nameProp != null) {
                identityModelProperties.put(PROPERTY_IDENTITY_TYPE_NAME, nameProp);
            } else {
                throw new IdentityException("Error initializing JpaIdentityStore - no valid identity type name property found.");
            }
        }
    }

    protected Property<Object> findNamedProperty(Class<?> targetClass, String... allowedNames) {
        List<Property<Object>> props = PropertyQueries.createQuery(targetClass).addCriteria(new TypedPropertyCriteria(String.class)).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.NAME)).getResultList();

        if (props.size() == 1) {
            return props.get(0);
        } else {
            props = PropertyQueries.createQuery(targetClass).addCriteria(new TypedPropertyCriteria(String.class)).addCriteria(new NamedPropertyCriteria(allowedNames)).getResultList();

            for (String name : allowedNames) {
                for (Property<Object> prop : props) {
                    if (name.equals(prop.getName())) {
                        return prop;
                    }
                }
            }
        }

        return null;
    }

    protected void configureCredentials() throws IdentityException {
        // If a credential entity has been explicitly configured, scan it
        if (credentialClass != null) {
            List<Property<Object>> props = PropertyQueries.createQuery(credentialClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.VALUE)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous credential value property in credential class "
                    + credentialClass.getName());
            } else {
                // Try scanning for a credential property also
                props = PropertyQueries.createQuery(credentialClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.CREDENTIAL)).getResultList();
                if (props.size() == 1) {
                    identityModelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
                } else if (props.size() > 1) {
                    throw new IdentityException(
                        "Ambiguous credential value property in credential class "
                        + credentialClass.getName());
                } else {
                    Property<Object> p = findNamedProperty(credentialClass, "credentialValue",
                        "password", "passwordHash", "credential", "value");
                    if (p != null) {
                        identityModelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
                    }
                }
            }

            // Scan for the credential identity property
            props = PropertyQueries.createQuery(credentialClass).addCriteria(new TypedPropertyCriteria(identityClass)).getResultList();
            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_CREDENTIAL_IDENTITY, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous identity property in credential class "
                    + credentialClass.getName());
            } else {
                // Scan for a named identity property
                props = PropertyQueries.createQuery(credentialClass).addCriteria(new NamedPropertyCriteria("identity", "identityObject")).getResultList();
                if (!props.isEmpty()) {
                    identityModelProperties.put(PROPERTY_CREDENTIAL_IDENTITY, props.get(0));
                } else {
                    throw new IdentityException("Error initializing JpaIdentityStore - no credential identity property found.");
                }
            }
        } else {
            // The credentials may be stored in the identity class
            List<Property<Object>> props = PropertyQueries.createQuery(identityClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.CREDENTIAL)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_CREDENTIAL_VALUE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous credential property in identity class "
                    + identityClass.getName());
            } else {
                Property<Object> p = findNamedProperty(identityClass, "credentialValue",
                    "password", "passwordHash", "credential", "value");
                if (p != null) {
                    identityModelProperties.put(PROPERTY_CREDENTIAL_VALUE, p);
                }
            }

            // If Credential is on Identity, it's see if Credential Type is too
            props = PropertyQueries.createQuery(identityClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.CREDENTIAL_TYPE)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous credential type property in identity class "
                    + identityClass.getName());
            } else {
                Property<Object> p = findNamedProperty(identityClass, "credentialType",
                    "identityObjectCredentialType", "type");
                if (p != null) {
                    identityModelProperties.put(PROPERTY_CREDENTIAL_TYPE, p);
                }
            }
        }

        if (!identityModelProperties.containsKey(PROPERTY_CREDENTIAL_VALUE)) {
            throw new IdentityException("Error initializing JpaIdentityStore - no credential value property found.");
        }

        // Scan for a credential type property
        if (identityModelProperties.get(PROPERTY_CREDENTIAL_TYPE) == null) { // We may have found it on identity
            List<Property<Object>> props = PropertyQueries.createQuery(credentialClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.TYPE)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous credential type property in credential class "
                    + credentialClass.getName());
            } else {
                props = PropertyQueries.createQuery(credentialClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.CREDENTIAL_TYPE)).getResultList();

                if (props.size() == 1) {
                    identityModelProperties.put(PROPERTY_CREDENTIAL_TYPE, props.get(0));
                } else if (props.size() > 1) {
                    throw new IdentityException(
                        "Ambiguous credential type property in credential class "
                        + credentialClass.getName());
                } else {
                    Property<Object> p = findNamedProperty(credentialClass, "credentialType",
                        "identityObjectCredentialType", "type");
                    if (p != null) {
                        identityModelProperties.put(PROPERTY_CREDENTIAL_TYPE, p);
                    }
                }
            }
        }

        Property<?> typeProp = identityModelProperties.get(PROPERTY_CREDENTIAL_TYPE);

        // If the credential type property isn't a String, then validate the lookup type
        if (!String.class.equals(typeProp.getJavaClass())) {
            Property<Object> nameProp = findNamedProperty(typeProp.getJavaClass(),
                "credentialObjectTypeName", "credentialTypeName", "typeName", "name");
            if (nameProp != null) {
                identityModelProperties.put(PROPERTY_CREDENTIAL_TYPE_NAME, nameProp);
            } else {
                throw new IdentityException("Error initializing JpaIdentityStore - no valid credential type name property found.");
            }
        }
    }

    protected void configureRelationships() throws IdentityException {
        if (relationshipClass == null) {
            throw new IdentityException("Error initializing JpaIdentityStore - relationshipClass not set.");
        }

        List<Property<Object>> props = PropertyQueries.createQuery(relationshipClass).addCriteria(new TypedPropertyCriteria(identityClass)).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.RELATIONSHIP_FROM)).getResultList();

        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_RELATIONSHIP_FROM, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                "Ambiguous relationshipFrom property in relationship class "
                + relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass, "relationshipFrom",
                "fromIdentityObject", "fromIdentity");
            if (p != null) {
                identityModelProperties.put(PROPERTY_RELATIONSHIP_FROM, p);
            } else {
                // Last resort - search for a property with a type of identityClass
                // and a "from" in its name
                props = PropertyQueries.createQuery(relationshipClass).addCriteria(new TypedPropertyCriteria(identityClass)).getResultList();

                for (Property<Object> prop : props) {
                    if (prop.getName().contains("from")) {
                        identityModelProperties.put(PROPERTY_RELATIONSHIP_FROM, prop);
                        break;
                    }
                }
            }
        }


        props = PropertyQueries.createQuery(relationshipClass).addCriteria(new TypedPropertyCriteria(identityClass)).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.RELATIONSHIP_TO)).getResultList();

        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_RELATIONSHIP_TO, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                "Ambiguous relationshipTo property in relationship class "
                + relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass, "relationshipTo",
                "toIdentityObject", "toIdentity");
            if (p != null) {
                identityModelProperties.put(PROPERTY_RELATIONSHIP_TO, p);
            } else {
                // Last resort - search for a property with a type of identityClass
                // and a "to" in its name
                props = PropertyQueries.createQuery(relationshipClass).addCriteria(new TypedPropertyCriteria(identityClass)).getResultList();

                for (Property<Object> prop : props) {
                    if (prop.getName().contains("to")) {
                        identityModelProperties.put(PROPERTY_RELATIONSHIP_TO, prop);
                        break;
                    }
                }
            }
        }

        props = PropertyQueries.createQuery(relationshipClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.TYPE)).getResultList();
        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_RELATIONSHIP_TYPE, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                "Ambiguous relationshipType property in relationship class "
                + relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass,
                "identityRelationshipType", "relationshipType", "type");
            if (p != null) {
                identityModelProperties.put(PROPERTY_RELATIONSHIP_TYPE, p);
            } else {
                props = PropertyQueries.createQuery(relationshipClass).getResultList();
                for (Property<Object> prop : props) {
                    if (prop.getName().contains("type")) {
                        identityModelProperties.put(PROPERTY_RELATIONSHIP_TYPE, prop);
                        break;
                    }
                }
            }
        }

        props = PropertyQueries.createQuery(relationshipClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.NAME)).addCriteria(new TypedPropertyCriteria(String.class)).getResultList();

        if (props.size() == 1) {
            identityModelProperties.put(PROPERTY_RELATIONSHIP_NAME, props.get(0));
        } else if (props.size() > 1) {
            throw new IdentityException(
                "Ambiguous relationship name property in relationship class "
                + relationshipClass.getName());
        } else {
            Property<Object> p = findNamedProperty(relationshipClass, "relationshipName", "name");
            if (p != null) {
                identityModelProperties.put(PROPERTY_RELATIONSHIP_NAME, p);
            }
        }

        if (identityModelProperties.containsKey(PROPERTY_RELATIONSHIP_NAME)) {
            namedRelationshipsSupported = true;
        }

        if (!identityModelProperties.containsKey(PROPERTY_RELATIONSHIP_FROM)) {
            throw new IdentityException(
                "Error initializing JpaIdentityStore - no valid relationship from property found.");
        }

        if (!identityModelProperties.containsKey(PROPERTY_RELATIONSHIP_TO)) {
            throw new IdentityException(
                "Error initializing JpaIdentityStore - no valid relationship to property found.");
        }

        if (!identityModelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE)) {
            throw new IdentityException(
                "Error initializing JpaIdentityStore - no valid relationship type property found.");
        }

        if (!identityModelProperties.containsKey(PROPERTY_RELATIONSHIP_NAME)) {
            throw new IdentityException(
                "Error initializing JpaIdentityStore - no valid relationship name property found.");
        }

        Class<?> typeClass = identityModelProperties.get(PROPERTY_RELATIONSHIP_TYPE).getJavaClass();
        if (!String.class.equals(typeClass)) {
            props = PropertyQueries.createQuery(typeClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.NAME)).addCriteria(new TypedPropertyCriteria(String.class)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_RELATIONSHIP_TYPE_NAME, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous relationship type name property in class "
                    + typeClass.getName());
            } else {
                Property<Object> p = findNamedProperty(typeClass, "relationshipTypeName",
                    "typeName", "name");
                if (p != null) {
                    identityModelProperties.put(PROPERTY_RELATIONSHIP_TYPE_NAME, p);
                }
            }

            if (!identityModelProperties.containsKey(PROPERTY_RELATIONSHIP_TYPE_NAME)) {
                throw new IdentityException(
                    "Error initializing JpaIdentityStore - no valid relationship type name property found");
            }
        }
    }

    protected void configureAttributes() throws IdentityException {
        // If an attribute class has been configured, scan it for attributes
        if (attributeClass != null) {
            List<Property<Object>> props = PropertyQueries.createQuery(attributeClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.NAME)).addCriteria(new TypedPropertyCriteria(String.class)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_ATTRIBUTE_NAME, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous attribute name property in class "
                    + attributeClass.getName());
            } else {
                Property<Object> prop = findNamedProperty(attributeClass,
                    "attributeName", "name");
                if (prop != null) {
                    identityModelProperties.put(PROPERTY_ATTRIBUTE_NAME, prop);
                }
            }

            props = PropertyQueries.createQuery(attributeClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.VALUE)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_ATTRIBUTE_VALUE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous attribute value property in class "
                    + attributeClass.getName());
            } else {
                Property<Object> prop = findNamedProperty(attributeClass,
                    "attributeValue", "value");
                if (prop != null) {
                    identityModelProperties.put(PROPERTY_ATTRIBUTE_VALUE, prop);
                }
            }

            props = PropertyQueries.createQuery(attributeClass).addCriteria(new TypedPropertyCriteria(identityClass)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_ATTRIBUTE_IDENTITY, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous identity property in attribute class "
                    + attributeClass.getName());
            } else {
                throw new IdentityException("Error initializing JpaIdentityStore - "
                    + "no attribute identity property found.");
            }

            props = PropertyQueries.createQuery(attributeClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.TYPE)).getResultList();

            if (props.size() == 1) {
                identityModelProperties.put(PROPERTY_ATTRIBUTE_TYPE, props.get(0));
            } else if (props.size() > 1) {
                throw new IdentityException(
                    "Ambiguous attribute type property in class "
                    + attributeClass.getName());
            }
        }

        // Scan for additional attributes in the identity class also
        List<Property<Object>> props = PropertyQueries.createQuery(identityClass).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.ATTRIBUTE)).getResultList();

        for (Property<Object> p : props) {
            String attribName = p.getAnnotatedElement().getAnnotation(IdentityProperty.class).attributeName();

            if (attributeProperties.containsKey(attribName)) {
                Property<Object> other = attributeProperties.get(attribName).getAttributeProperty();

                throw new IdentityException("Multiple properties defined for attribute [" + attribName + "] - "
                    + "Property: " + other.getDeclaringClass().getName() + "." + other.getAnnotatedElement().toString()
                    + ", Property: " + p.getDeclaringClass().getName() + "." + p.getAnnotatedElement().toString());
            }

            attributeProperties.put(attribName, new MappedAttribute(null, p));
        }

        // scan any entity classes referenced by the identity class also
        props = PropertyQueries.createQuery(identityClass).getResultList();

        for (Property<Object> p : props) {
            if (!p.isReadOnly() && p.getJavaClass().isAnnotationPresent(Entity.class)) {
                List<Property<Object>> pp = PropertyQueries.createQuery(p.getJavaClass()).addCriteria(new IdentityPropertyTypeCriteria(PropertyType.ATTRIBUTE)).getResultList();

                for (Property<Object> attributeProperty : pp) {
                    String attribName = attributeProperty.getAnnotatedElement().getAnnotation(IdentityProperty.class).attributeName();

                    if (attributeProperties.containsKey(attribName)) {
                        Property<Object> other = attributeProperties.get(attribName).getAttributeProperty();

                        throw new IdentityException("Multiple properties defined for attribute [" + attribName + "] - "
                            + "Property: " + other.getDeclaringClass().getName() + "." + other.getAnnotatedElement().toString()
                            + ", Property: " + attributeProperty.getDeclaringClass().getName() + "." + attributeProperty.getAnnotatedElement().toString());
                    }

                    attributeProperties.put(attribName, new MappedAttribute(p, attributeProperty));
                }
            }
        }
    }

    protected void configureRoleTypeName() {
        Property<Object> relationshipNameProp = findNamedProperty(roleTypeClass, "name");
        if (relationshipNameProp != null) {
            identityModelProperties.put(PROPERTY_ROLE_TYPE_NAME, relationshipNameProp);
        }
    }

    protected class AttributeValue {

        private String encoded;
        private String type;

        public AttributeValue(String encoded, String type) {
            this.encoded = encoded;
            this.type = type;
        }

        public String getEncoded() {
            return encoded;
        }

        public String getType() {
            return type;
        }
    }

//***************************************************************************************************
//***************************************************************************************************
    public Map<String, MappedAttribute> getAttributeProperties() {
        return attributeProperties;
    }

    public Map<String, Property<Object>> getIdentityModelProperties() {
        return identityModelProperties;
    }

    public boolean isNamedRelationshipsSupported() {
        return namedRelationshipsSupported;
    }
}
