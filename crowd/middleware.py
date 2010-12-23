from crowd.backend import CrowdBackend
from datetime import  datetime, timedelta
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import AnonymousUser

__author__ = 'sannies'


class CrowdSSOAuthenticationMiddleware(object):
    crowdBackend = CrowdBackend()

    def process_request(self, request):
        try:
            crowd_token = request.COOKIES["crowd.token_key"]
        except KeyError:
            crowd_token = None

        if crowd_token is None:
            return None
        else:
            if request.user.is_anonymous():
                kwargs = {CrowdBackend.REMOTE_ADDRESS: request.META["REMOTE_ADDR"],
                          CrowdBackend.USER_AGENT: request.META["HTTP_USER_AGENT"],
                          CrowdBackend.REMOTE_HOST: request.META["REMOTE_HOST"]}
                crowdUser = self.crowdBackend.findUserByToken(crowd_token, **kwargs)

                if crowdUser is not None:
                    auth_login(request, crowdUser)
                return None
            else:
                return None


    def process_response(self, request, response):
        try:
            crowd_token = request.COOKIES["crowd.token_key"]
        except KeyError:
            crowd_token = None
        if request.user.is_authenticated() and crowd_token is None:
            cookieInfo = self.crowdBackend.getCookieInfo()
            kwargs = {CrowdBackend.REMOTE_ADDRESS: request.META["REMOTE_ADDR"],
                      CrowdBackend.USER_AGENT: request.META["HTTP_USER_AGENT"],
                      CrowdBackend.REMOTE_HOST: request.META["REMOTE_HOST"]}            
            principalToken = self.crowdBackend.getPrincipalToken(request.user.username, **kwargs)
            max_age = 30 * 365 * 24 * 60 * 60
            expires = datetime.strftime(datetime.utcnow() + timedelta(seconds=max_age), "%a, %d-%b-%Y %H:%M:%S GMT")
            response.set_cookie("crowd.token_key",
                        principalToken, max_age=max_age,
                        expires=expires, domain=cookieInfo.domain,
                        path="/",
                        secure=cookieInfo.secure)

        return response

