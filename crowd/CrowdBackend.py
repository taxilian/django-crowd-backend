from suds.client import Client
import suds.xsd.doctor as dr
from django.contrib.auth.models import User, Group


class CrowdBackend:
    "Atlassian Crowd Authentication Backend"
    crowdClient = None
    authenticationToken = None

    def authenticate(self, username=None, password=None):
        if (self.crowdClient is None):
            self.crowdClient = self.createClient()

        if (self.authenticationToken is None):
            self.authenticationToken = self.authenticateApplication(self.crowdClient)


        save_user = False

        principalToken = self.crowdClient.service.authenticatePrincipalSimple(self.authenticationToken, username, password)
        user, created = User.objects.get_or_create(username=username)

        if created:
            #logger.debug("Created Django user %s", username)
            user.set_unusable_password()
            save_user = True

        if( crowd_settings.AUTH_CROWD_ALWAYS_UPDATE_USER or created):
            #logger.debug("Populating Django user %s", username)
            self.populate_user(user)
            save_user = True

        if crowd_settings.AUTH_CROWD_MIRROR_GROUPS:
            self.populate_groups( user)
            save_user = True

        if save_user:
            user.save()

        return user

    def get_user(self, user_id):
        user = None

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            pass

        return user



    def authenticateApplication(self, client):
        auth_context = client.factory.create('ns1:ApplicationAuthenticationContext')
        auth_context.name = "django"
        auth_context.credential.credential = "sep-2010"
        return client.service.authenticateApplication(auth_context)

    def createClient(self):

        # The following dictionary has the targetNamespace as the key and a list
        # of namespaces that need to be imported as the value for that key
        patches = {"urn:SecurityServer": ["http://authentication.integration.crowd.atlassian.com",
                                          "http://soap.integration.crowd.atlassian.com",
                                          "http://exception.integration.crowd.atlassian.com",
                                          "http://rmi.java"],
                   "http://soap.integration.crowd.atlassian.com": ["urn:SecurityServer"]}

        # Create an ImportDoctor to use
        doctor = dr.ImportDoctor()

        # Patch all the imports into the proper targetNamespaces
        for targetNamespace in patches:
            for ns_import in patches[targetNamespace]:
                imp = dr.Import(ns_import)
                imp.filter.add(targetNamespace)
                doctor.add(imp)

            # Create the SOAP client, doctoring it to fix imports
        return Client(crowd_settings.AUTH_CROWD_SERVER_URI, doctor=doctor)

    def populate_user(self, user):
        soap_principal = self.crowdClient.service.findPrincipalByName( self.authenticationToken, user.username )
        user.is_active = True
        for soapAttribute in soap_principal.attributes[0]:
            if (soapAttribute.name == "mail"):
                user.email = soapAttribute.values[0]
            if(soapAttribute.name == "givenName"):
                user.first_name = soapAttribute.values[0]
            if(soapAttribute.name == "sn"):
                user.last_name = soapAttribute.values[0]
        pass

    def populate_groups(self, user):
        arrayOfGroups = self.crowdClient.service.findGroupMemberships(self.authenticationToken, user.username)
        user.groups.clear()

        for crowdgroup in arrayOfGroups[0]:
            group, created = Group.objects.get_or_create(name=crowdgroup)
            if created:
                group.save()

            user.groups.add(group)
            if (group.name == crowd_settings.AUTH_CROWD_SUPERUSER_GROUP):
                user.is_superuser = True
            if (group.name == crowd_settings.AUTH_CROWD_STAFF_GROUP):
                user.is_staff = True


        pass


class CrowdSettings(object):
    """
    This is a simple class to take the place of the global settings object. An
    instance will contain all of our settings as attributes, with default values
    if they are not specified by the configuration.
    """
    defaults = {
        'AUTH_CROWD_ALWAYS_UPDATE_USER': True,
        'AUTH_CROWD_MIRROR_GROUPS': True,
        'AUTH_CROWD_STAFF_GROUP': 'staff',
        'AUTH_CROWD_SUPERUSER_GROUP': 'superuser',
        'AUTH_CROWD_SERVER_URI': 'http://127.0.0.1:8095/crowd/services/SecurityServer?wsdl'
    }

    def __init__(self):
        """
        Loads our settings from django.conf.settings, applying defaults for any
        that are omitted.
        """
        from django.conf import settings

        for name, default in self.defaults.iteritems():
            value = getattr(settings, name, default)
            setattr(self, name, value)


# Our global settings object
crowd_settings = CrowdSettings()
