from crowd.backend import CrowdBackend
from datetime import  datetime, timedelta
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import AnonymousUser

__author__ = 'sannies'


class CrowdSSOAuthenticationMiddleware(object):
    crowdBackend = CrowdBackend()
    crowdUserLoggedIn = False

    def process_request(self, request):
        try:
            crowd_token = request.COOKIES["crowd.token_key"]
        except KeyError:
            return None

        if request.user.is_anonymous():
            validationFactors = self.crowdBackend.getValidationFactors(request)
            crowdUser = self.crowdBackend.findUserByToken(crowd_token, validationFactors)
            if crowdUser is not None:
                crowdUser.backend = "%s.%s" % (self.crowdBackend.__module__, self.crowdBackend.__class__.__name__)
                auth_login(request, crowdUser)
                self.crowdUserLoggedIn = True
            return None
        else:
            if hasattr(request.user, 'isCrowdUser') and request.user.isCrowdUser:
                self.crowdUserLoggedIn = True
            return None


    def process_response(self, request, response):
        try:
            crowd_token = request.COOKIES["crowd.token_key"]
        except KeyError:
            crowd_token = None
        if request.user.is_authenticated() and crowd_token is None:
            cookieInfo = self.crowdBackend.getCookieInfo()
            validationFactors = self.crowdBackend.getValidationFactors(request)
            principalToken = self.crowdBackend.getPrincipalToken(request.user.username, validationFactors)
            max_age = 30 * 365 * 24 * 60 * 60
            expires = datetime.strftime(datetime.utcnow() + timedelta(seconds=max_age), "%a, %d-%b-%Y %H:%M:%S GMT")
            response.set_cookie("crowd.token_key",
                        principalToken, max_age=max_age,
                        expires=expires, domain=cookieInfo.domain,
                        path="/",
                        secure=cookieInfo.secure)
        else:
            if request.user is AnonymousUser and crowd_token is not None and self.crowdUserLoggedIn:
                self.crowdBackend.invalidateToken()


        return response


