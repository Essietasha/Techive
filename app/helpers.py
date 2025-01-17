from functools import wraps
from flask import redirect, render_template, session, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def error(message, code):
    return render_template("error.html", message=message), code


def liked_by_user(likes, user_id):
    return any(like.user_id == user_id for like in likes)


# import requests

# from flask import redirect, render_template, session
# from functools import wraps


# def error(message, code=400):
#     def escape(s):
#         for old, new in [
#             ("-", "--"),
#             (" ", "-"),
#             ("_", "__"),
#             ("?", "~q"),
#             ("%", "~p"),
#             ("#", "~h"),
#             ("/", "~s"),
#             ('"', "''"),
#         ]:
#             s = s.replace(old, new)
#         return s

#     return render_template("error.html", top=code, bottom=escape(message)), code


# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if session.get("user_id") is None:
#             return redirect("/login")
#         return f(*args, **kwargs)

#     return decorated_function
