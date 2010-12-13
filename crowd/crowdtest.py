__author__ = 'sannies'


from suds.client import Client
import suds.xsd.doctor as dr

wsdlurl = 'http://hoff.coremedia.com:8095/crowd/services/SecurityServer?wsdl'
# The following dictionary has the targetNamespace as the key and a list
# of namespaces that need to be imported as the value for that key
patches = { "urn:SecurityServer": ["http://authentication.integration.crowd.atlassian.com",
    "http://soap.integration.crowd.atlassian.com","http://exception.integration.crowd.atlassian.com",
    "http://rmi.java"] ,
    "http://soap.integration.crowd.atlassian.com": ["urn:SecurityServer"] }

# Create an ImportDoctor to use
doctor = dr.ImportDoctor()

# Patch all the imports into the proper targetNamespaces
for targetNamespace in patches:
    for ns_import in patches[targetNamespace]:
        imp = dr.Import(ns_import)
        imp.filter.add(targetNamespace)
        doctor.add(imp)

# Create the SOAP client, doctoring it to fix imports
client = Client(wsdlurl,doctor=doctor)
print(client)

auth_context = client.factory.create('ns1:ApplicationAuthenticationContext')
auth_context.name = "django"
auth_context.credential.credential = "sep-2010"

token = client.service.authenticateApplication(auth_context)

principalToken = client.service.authenticatePrincipalSimple(token, 'sannies', 'sannies')
print client.service.findGroupMemberships(token,'sannies')
principal = client.service.findPrincipalByToken(token, principalToken )
for soapAttribute in principal.attributes[0]:
    print soapAttribute
pass


