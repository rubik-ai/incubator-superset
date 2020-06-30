import logging
import os

from cachelib.file import FileSystemCache
logger = logging.getLogger()

def get_env_variable(var_name, default=None):
    """Get the environment variable or raise exception."""
    try:
        return os.environ[var_name]
    except KeyError:
        if default is not None:
            return default
        else:
            error_msg = "The environment variable {} was missing, abort...".format(
                var_name
            )
            raise EnvironmentError(error_msg)

DATABASE_DIALECT = get_env_variable("DATABASE_DIALECT")
DATABASE_USER = get_env_variable("DATABASE_USER")
DATABASE_PASSWORD = get_env_variable("DATABASE_PASSWORD")
DATABASE_HOST = get_env_variable("DATABASE_HOST")
DATABASE_PORT = get_env_variable("DATABASE_PORT")
DATABASE_DB = get_env_variable("DATABASE_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = "%s://%s:%s@%s:%s/%s" % (
    DATABASE_DIALECT,
    DATABASE_USER,
    DATABASE_PASSWORD,
    DATABASE_HOST,
    DATABASE_PORT,
    DATABASE_DB,
)
SQLALCHEMY_ECHO = True
REDIS_HOST = get_env_variable("REDIS_HOST")
REDIS_PORT = get_env_variable("REDIS_PORT")
REDIS_CELERY_DB = get_env_variable("REDIS_CELERY_DB", 0)
REDIS_RESULTS_DB = get_env_variable("REDIS_CELERY_DB", 1)

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")


class CeleryConfig(object):
    BROKER_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    CELERY_IMPORTS = ("superset.sql_lab",)
    CELERY_RESULT_BACKEND = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    CELERY_ANNOTATIONS = {"tasks.add": {"rate_limit": "10/s"}}
    CELERY_TASK_PROTOCOL = 1


CELERY_CONFIG = CeleryConfig
SQLLAB_CTAS_NO_LIMIT = True

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    from superset_config_docker import *  # noqa
    import superset_config_docker

    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")

# CACHE_CONFIG = {
#     'CACHE_TYPE': 'redis',
#     'CACHE_DEFAULT_TIMEOUT': 60 * 60 * 24, # 1 day default (in secs)
#     'CACHE_KEY_PREFIX': 'superset_results',
#     'CACHE_REDIS_URL': 'redis://superset_cache:6379/0',
# }

DEFAULT_FEATURE_FLAGS = {
    'CLIENT_CACHE': True,
    'ENABLE_EXPLORE_JSON_CSRF_PROTECTION': False,
    'PRESTO_EXPAND_DATA': True,
}

from flask_appbuilder.security.manager import AUTH_OAUTH

logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('werkzeug').setLevel(logging.CRITICAL)

def get_env_variable(var_name, default=None):
    """Get the environment variable or raise exception."""
    try:
        return os.environ[var_name]
    except KeyError:
        if default is not None:
            return default
        else:
            error_msg = 'The environment variable {} was missing, abort...'\
                        .format(var_name)
            raise EnvironmentError(error_msg)

PUBLIC_ROLE_LIKE_GAMMA = True

# ====== Start Login ===========
# ref: https://gist.github.com/ktmud/2475282a166893e5d17039c308cbe50d

# AUTH_TYPE = 0 | 1 | 2 | 3 | 4
# 0 = Open ID
# 1 = Database style (user/password)
# 2 = LDAP, use AUTH_LDAP_SERVER also
# 3 = uses web server environ var REMOTE_USER
# 4 = USE ONE OR MANY OAUTH PROVIDERS

AUTH_TYPE = int(get_env_variable('MORPHEUS_AUTH_TYPE', '1'))

# ref: https://superset.incubator.apache.org/installation.html#middleware
# class RemoteUserMiddleware:
#     def __init__(self, app):
#         self.app = app
#     def __call__(self, environ, start_response):
#         user = environ.pop('HTTP_X_PROXY_REMOTE_USER', 'admin')
#         environ['REMOTE_USER'] = user
#         return self.app(environ, start_response)
#
# ADDITIONAL_MIDDLEWARE = [RemoteUserMiddleware, ]

AUTH_USER_REGISTRATION = True  # allow self-registration (login creates a user)
AUTH_USER_REGISTRATION_ROLE = "Admin"  # default is a Gamma user

OIDC_BASE_URL = get_env_variable('OIDC_BASE_URL') #'https://supposedly-rested-snake.dataos.io/oidc/'
OIDC_CLIENT_KEY = get_env_variable('OIDC_CLIENT_KEY') #'dataos_morpheus'
OIDC_CLIENT_SECRET = get_env_variable('OIDC_CLIENT_SECRET') #'865E89CE2F865FC9'

OIDC_ACCESS_TOKEN_URL = OIDC_BASE_URL + 'token'
OIDC_AUTH_URL = OIDC_BASE_URL + 'auth'
OIDC_NAME = 'dex'

OAUTH_PROVIDERS = [{
    'name': OIDC_NAME,
    'token_key': 'access_token', # Name of the token in the response of access_token_url
    'icon': 'fa-address-card',   # Icon for the provider
    'remote_app': {
        'consumer_key': OIDC_CLIENT_KEY,
        'consumer_secret': OIDC_CLIENT_SECRET,
        'request_token_params': {
            'scope': 'openid email profile groups'
        },
        'access_token_method': 'POST',
        'base_url': OIDC_BASE_URL,
        'access_token_url': OIDC_ACCESS_TOKEN_URL,
        'authorize_url': OIDC_AUTH_URL
    }
}]

from superset.security import SupersetSecurityManager
logger = logging.getLogger('dataos_login')
logger.debug('========>>> %s', AUTH_TYPE)

class CustomSsoSecurityManager(SupersetSecurityManager):
    def oauth_user_info(self, provider, response=None):
        logger.debug("oauth_user_info() provider=%s", provider)
        if provider == OIDC_NAME:
            res = self.appbuilder.sm.oauth_remotes[provider].get('userinfo') # UserInfo call
            logger.debug("UserInfo, status=%s, data=%s", res.status, res.data)

            if res.status != 200:
                logger.error('Failed to obtain user info: %s', res.data)
                return

            me = res.data
            prefix = ''
            groups = [
                x.replace(prefix, '').strip() for x in me['groups']
                if x.startswith(prefix)
            ]
            groups.append('Admin')
            return {
                'id' : me['name'],
                'username': me['name'],
                'name' : me['name'],
                'email' : me['email'],
                'roles': groups,
            }

    # def auth_user_oauth(self, userinfo):
    #     logger.debug("oauth_user_info() userinfo=%s", userinfo)
    #     user = super(CustomSsoSecurityManager, self).auth_user_oauth(userinfo)
    #     logger.debug("*******************************************")
    #     logger.debug("oauth_user_info() user=%s", user)
    #     roles = [self.find_role(x) for x in userinfo['roles']]
    #     roles = [x for x in roles if x is not None]
    #     user.roles = roles
    #     logger.debug("*******************************************")
    #     logger.debug(' Update <User: %s> role to %s', user.username, roles)
    #     self.update_user(user)  # update user roles
    #     return user

CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager
# ====== End Login ============
