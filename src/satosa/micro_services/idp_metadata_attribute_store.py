"""
SATOSA microservice that includes in the assertion 
attributes taken from SAML metadata about the SAML 
IdP used for authentication.

The attributes that may be asserted from the SAML
metadata for the IdP include

<mdui:DisplayName>
<OrganiationName>
<OrganizationDisplayName>

A typical configuration would be

module: idp_metadata_attribute_store.IdpMetadataAttributeStore
name: IdpMetadataAttributeStore
config:
  default:
      display_name:
          # SATOSA internal attribute name to use  
          internal_attribute_name: idpdisplayname
          # Language preference with 'en' or English as default
          lang: en
      entity_id:
          internal_attribute_name: idpentityid
      organization_name:
          internal_attribute_name: idporgname
          lang: en
      organization_display_name:
          internal_attribute_name: idporgdisplayname
          lang: en
          
  # Configuration may also be done per-IdP with any
  # missing parameters taken from the default if any.
  # The configuration key is the entityID of the IdP.
  #
  # For example:
  https://login.myorg.edu/idp/shibboleth:
      display_name:
          internal_attribute_name: othername
          lang: jp
  # The microservice may be configured to ignore a particular IdP.
  https://login.other.org.edu/idp/shibboleth:
    ignore: true
"""

import satosa.micro_services.base
from satosa.logging_util import satosa_logging
from satosa.exception import SATOSAError
from satosa.context import Context

import copy
import logging

logger = logging.getLogger(__name__)

class IdpMetadataAttributeStoreError(SATOSAError):
    """
    LDAP attribute store error
    """
    pass

class IdpMetadataAttributeStore(satosa.micro_services.base.ResponseMicroService):
    """
    Use the metadata store attached to the proxy SP in the context
    to lookup metadata about the IdP entity making the assertion 
    and include metadata details as attributes in the assertion sent
    to the SP that made the request.
    """

    config_defaults = { 'ignore' : False }

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if 'default' in config and "" in config:
            msg = """Use either 'default' or "" in config but not both"""
            satosa_logging(logger, logging.ERROR, msg, None)
            raise IdpMetadataAttributeStoreError(msg)

        if "" in config:
            config['default'] = config.pop("")

        if 'default' not in config:
            msg = "No default configuration is present"
            satosa_logging(logger, logging.ERROR, msg, None)
            raise IdpMetadataAttributeStoreError(msg)

        self.config = {}

        # Process the default configuration first then any per-IdP overrides.
        idp_list = ['default']
        idp_list.extend([ key for key in config.keys() if key != 'default' ])

        for idp in idp_list:
            if not isinstance(config[idp], dict):
                msg = "Configuration value for {} must be a dictionary"
                satosa_logging(logger, logging.ERROR, msg, None)
                raise IdpMetadataAttributeStoreError(msg)

            # Initialize configuration using module defaults then update
            # with configuration defaults and then per-IdP overrides.
            idp_config = copy.deepcopy(IdpMetadataAttributeStore.config_defaults)
            if 'default' in self.config:
                idp_config.update(self.config['default'])
            idp_config.update(config[idp])

            self.config[idp] = idp_config

        satosa_logging(logger, logging.INFO, "IdP Metadata Attribute Store microservice initialized", None)

    def _first_lang_element_text(self, elements, lang='en'):
        """
        Loop over the list representing XML elements that contain text and find
        the first text value for the input lang where 'en' or English is the
        default lang.

        Each item in the list is a dictionary with keys

            __class__
            lang
            text

        as expected from the metadata returned for an entity by the MetadataStore
        class from pysaml2.

        If no element has the input lang then return the text from the first 
        element.

        If no element has text then return an empty string.
        """
        for e in elements:
            if lang in e:
                if 'text' in e:
                    return e['text']

        for e in elements:
            if 'text' in e:
                return e['text']

        return ''

    def process(self, context, data):
        """
        Default interface for microservices. Process the input data for
        the input context.
        """
        self.context = context

        # Find the entityID for the IdP that issued the assertion.
        try:
            idp_entity_id = data.to_dict()['auth_info']['issuer']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "Unable to determine the entityID for the IdP issuer", context.state)
            return super().process(context, data)

        # Get the configuration for the IdP.
        if idp_entity_id in self.config.keys():
            config = self.config[idp_entity_id]
        else:
            config = self.config['default']

        satosa_logging(logger, logging.DEBUG, "Using config {}".format(config), context.state)

        # Log the entityID of the authenticating IdP.
        satosa_logging(logger, logging.INFO, "entityID for authenticating IdP is {}".format(idp_entity_id), context.state)

        # Ignore this IdP if so configured.
        if config['ignore']:
            satosa_logging(logger, logging.INFO, "Ignoring IdP {}".format(idp_entity_id), context.state)
            return super().process(context, data)

        # Set the entityID attribute if so configured.
        if 'entity_id' in config:
            data.attributes[config['entity_id']['internal_attribute_name']] = idp_entity_id

        # Get the metadata store the SP for the proxy is using. This
        # will be an instance of the class MetadataStore from mdstore.py
        # in pysaml2.
        metadata_store = context.get_decoration(Context.KEY_BACKEND_METADATA_STORE)

        # Get the metadata for the IdP.
        try:
            metadata = metadata_store[idp_entity_id]
        except Exception as err:
            satosa_logging(logger, logging.ERROR, "Unable to retrieve metadata for IdP {}".format(idp_entity_id), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "Metadata for IdP {} is {}".format(idp_entity_id, metadata), context.state)

        # Find the mdui:DisplayName for the IdP if so configured.
        if 'display_name' in config:
            lang = config['display_name'].get('lang', 'en')
            try:
                # We assume there is only one IDPSSODescriptor in the IdP metadata.
                extensions = metadata['idpsso_descriptor'][0]['extensions']['extension_elements']
                for e in extensions:
                    if e['__class__'] == 'urn:oasis:names:tc:SAML:metadata:ui&UIInfo':
                        display_name_elements = e['display_name']
                        display_name = self._first_lang_element_text(display_name_elements, lang)
                        break

                if display_name:
                    satosa_logging(logger, logging.DEBUG, "display_name is {}".format(display_name), context.state)
                    data.attributes[config['display_name']['internal_attribute_name']] = display_name
                        
            except Exception as err:
                satosa_logging(logger, logging.WARN, "Unable to determine display name for {}".format(idp_entity_id), context.state)

        # Find the OrganizationDisplayName for the IdP if so configured.
        if 'organization_display_name' in config:
            lang = config['organization_display_name'].get('lang', 'en')
            try:
                org_display_name_elements = metadata['organization']['organization_display_name']
                organization_display_name = self._first_lang_element_text(org_display_name_elements, lang)

                if organization_display_name:
                    satosa_logging(logger, logging.DEBUG, "organization_display_name is {}".format(organization_display_name), context.state)
                    data.attributes[config['organization_display_name']['internal_attribute_name']] = organization_display_name

            except Exception as err:
                satosa_logging(logger, logging.WARN, "Unable to determine organization display name for {}".format(idp_entity_id), context.state)

        # Find the OrganizationName for the IdP if so configured.
        if 'organization_name' in config:
            lang = config['organization_name'].get('lang', 'en')
            try:
                org_name_elements = metadata['organization']['organization_name']
                organization_name = self._first_lang_element_text(org_name_elements, lang)

                if organization_name:
                    satosa_logging(logger, logging.DEBUG, "organization_name is {}".format(organization_name), context.state)
                    data.attributes[config['organization_name']['internal_attribute_name']] = organization_name

            except Exception as err:
                satosa_logging(logger, logging.WARN, "Unable to determine organization display name for {}".format(idp_entity_id), context.state)
            
        satosa_logging(logger, logging.DEBUG, "Returning data.attributes {}".format(str(data.attributes)), context.state)
        return super().process(context, data)
