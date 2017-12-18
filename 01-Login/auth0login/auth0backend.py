from six.moves.urllib import request
from jose import jwt
from social_core.backends.oauth import BaseOAuth2


class Auth0(BaseOAuth2):
    """Auth0 OAuth authentication backend"""
    name = 'auth0'
    SCOPE_SEPARATOR = ' '
    ACCESS_TOKEN_METHOD = 'POST'
    EXTRA_DATA = [
        ('picture', 'picture'),
        ('contact_id', 'contact_id'),
        ('tags', 'tags')
    ]

    def authorization_url(self):
        return "https://" + self.setting('DOMAIN') + "/authorize"

    def access_token_url(self):
        return "https://" + self.setting('DOMAIN') + "/oauth/token"

    def get_user_id(self, details, response):
        """Return current user id."""
        return details['user_id']

    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        idToken = response.get('id_token')
        jwks = request.urlopen("https://" + self.setting('DOMAIN') + "/.well-known/jwks.json")
        issuer = "https://" + self.setting('DOMAIN') + "/"
        audience = self.setting('KEY') #CLIENT_ID
        payload = jwt.decode(idToken, jwks.read(), algorithms=['RS256'], audience=audience, issuer=issuer)

        return {'username': payload['preferred_username'],
                'first_name': payload['name'],
                'picture': payload['picture'],
                'contact_id': payload['https://tjnative.com/contact_id'],
                'tags': payload['https://tjnative.com/tags'],
                'user_id': payload['sub']}
