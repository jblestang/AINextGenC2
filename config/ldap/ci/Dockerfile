FROM osixia/openldap:1.5.0

ENV LDAP_ORGANISATION="NATO FMN Exercise"
ENV LDAP_DOMAIN="nato.int"
ENV LDAP_ADMIN_PASSWORD="ci-ldap-admin"
ENV LDAP_CONFIG_PASSWORD="config"
ENV LDAP_TLS="false"
ENV LDAP_REMOVE_CONFIG_AFTER_SETUP="true"

COPY schema/ /container/service/slapd/assets/config/bootstrap/schema/custom/
COPY ldif/ /container/service/slapd/assets/config/bootstrap/ldif/custom/
