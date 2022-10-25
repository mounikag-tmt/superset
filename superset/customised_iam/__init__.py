from flask import request, g, current_app
from flask_login import login_user, logout_user
import logging
import typing as t
import jwt
# from superset.app import SupersetAppInitializer
# from superset import security_manager as sm

# Middleware to extract user from header HTTP_X_PROXY_REMOTE_USER
# and place it at REMOTE_USER


class RemoteUserLogin(object):

   def __init__(self, app):
        self.app = app

   def before_request(self):
        print("==================before_request in RemoteUserLogin")
        user = self.log_user(request.environ)
        if not user:
            raise Exception("Invalid login or user not found")

def log_user(self, environ):
    username = self.get_username(environ)
    logging.info("REMOTE_USER Checking logged user")
    print("REMOTE_USER Checking logged user")
    if hasattr(g, "user") and hasattr(g.user, "username"):
       if g.user.username == username:
            logging.info("REMOTE_USER user already logged")
            return g.user
    else:
       logout_user()

    # user = sm.find_user(username = username)
    # logging.info("REMOTE_USER Look up user: %s", user)
    # if user:
      # logging.info("REMOTE_USER Login_user: %s", user)
    # login_user(user)
    #return user

    def get_username(self, environ):
        user = environ.pop('HTTP_X_PROXY_REMOTE_USER', None)

        if not user and self.app.debug:
            user = environ.get("werkzeug.request").args.get("logme")
        if user:
            logging.error("Logging user from request. Remove me ASAP!!!: %s", user)

        environ['REMOTE_USER'] = user
        return user

    def before_request(self):
        user = self.log_user(request.environ)
        if not user:
            raise Exception("Invalid login or user not found")

# def app_init(app):
   # logging.info("Resgistering RemoteUserLogin========")
   # print("Resgistering RemoteUserLogin============")
   # app.before_request(RemoteUserLogin(app).before_request)
   # return SupersetAppInitializer(app)

# APP_INITIALIZER = app_init


from flask.sessions import SecureCookieSessionInterface, SessionMixin, \
    SecureCookieSession


class IamSecureCookieSessionInterface(SecureCookieSessionInterface):
    def open_session(
        self, app: "Flask", request: "Request"
    ) -> t.Optional[SecureCookieSession]:
        print("sessions===open_session==========")
        s = self.get_signing_serializer(app)
        print("sessions===get_signing_serializer=====s=====", s)
        if s is None:
            return None
        print("print all cookies: ", request.cookies.keys())
        session_val = request.cookies.get(self.get_cookie_name(app))
        iam_access_token = request.cookies.get("iam-access-token")
        print("getting value: for cookie-name: ", self.get_cookie_name(app), session_val)
        # existing value
        # if not val:
           # return self.session_class()
        if session_val or iam_access_token:
            if session_val:
                max_age = int(app.permanent_session_lifetime.total_seconds())
                try:
                    data = s.loads(session_val, max_age=max_age)
                    print("daata after load: ", data)
                    return self.session_class(data)
                except BadSignature:
                    return self.session_class()
            if iam_access_token:
                decoded_access_token = jwt.decode(iam_access_token, 'TrimindTech', algorithms=['HS512'])
                print("iam_sessions.decoded_access_token", decoded_access_token)
                iam_user_details = decoded_access_token.get("iamUserDetails")
                username = iam_user_details.get("name")
                security_manager = current_app.appbuilder.sm
                user = security_manager.find_user(username=username)
                user_id = getattr(user, current_app.login_manager.id_attribute)()
                print("iam_sessions.userId :", user_id)
                data = {"user_id": user_id}
                print("iam_sessions.data for session ", data)
                return self.session_class(data)
        else:
            return self.session_class()

    def save_session(
        self, app: "Flask", session: SessionMixin, response: "Response"
    ) -> None:
        print("SecureCookieSessionInterface===save_session overriden method called")
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)

        # If the session is modified to be empty, remove the cookie.
        # If the session is empty, return without setting the cookie.
        print("print session : ", session)
        if not session:
            # print( "SecureCookieSessionInterface====session modified??==so delete_cookie==")
            if session.modified:
                # print("SecureCookieSessionInterface===session delete_cookie====")
                response.delete_cookie(
                    name, domain=domain, path=path, secure=secure, samesite=samesite
                )

            return

        # Add a "Vary: Cookie" header if the session was accessed at all.
        if session.accessed:
            response.vary.add("Cookie")

        if not self.should_set_cookie(app, session):
            return

        httponly = self.get_cookie_httponly(app)
        expires = self.get_expiration_time(app, session)
        # print("session-=======")
        # print(session)
        # print("app=======")
        # print(app)
        # print("self.get_signing_serializer(app)-=======")
        token = session.get("_token")
        if token:
            session.pop("_token")
        print("session before encrypt ", session)
        val = self.get_signing_serializer(app).dumps(dict(session))  # type: ignore
        # print("SecureCookieSessionInterface===name: "+name+ " ; "+val)
        # print("SecureCookieSessionInterface===session.expires")
        # print(expires)
        # print("SecureCookieSessionInterface===session.httponly")
        # print(httponly)
        # print("SecureCookieSessionInterface===session.domain")
        # print(domain)
        # print("SecureCookieSessionInterface===session.path")
        # print(path)
        # print("SecureCookieSessionInterface===session.secure")
        # print(secure)
        # print("SecureCookieSessionInterface===session.samesite")
        # print(samesite)
        # response.set_cookie(
        #     name,
        #     val,  # type: ignore
        #     expires=expires,
        #     httponly=httponly,
        #     domain=domain,
        #     path=path,
        #     secure=secure,
        #     samesite=samesite,
        # )
        print("================setting token tooo-")
        if token:
            response.set_cookie(
                "iam-access-token", token,
                expires=expires,
                httponly=httponly,
                domain=domain,
                path=path,
                secure=secure,
                samesite=samesite,
            )

