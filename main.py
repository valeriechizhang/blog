import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

SECRET = "thisisasecretkey"

# helper functions (not included in any class):

# render_str returns a web page template (HTML) with parameters input
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# it encrypts a string variable with a secrect key using hmac
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())

# it checks whether a secured value has been illegally modified
# if not, it returns the original string value
def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val

# user authentication functions

# It creates a salt string to help with password encryption/
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# It hashes the password using a salt before store it in the user database.
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# It reads an encrypted password.
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


## DATABASE (User and Posts)##

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    # find user by id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    # find user by username
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # add a new user into the database
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)

    # login a user by verifying the password
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    # it helps display the content for a certain blog post
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post-format.html", p = self)



# the handler is inherited by other handlers
# it provides some universal functions for the application
class Handler(webapp2.RequestHandler):

    # below 3 functions help render content for the web pages
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Set Cookies using encrypted message
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Read encrypted Cookies and return the value if it is legal
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Set the Cookies with the user_id
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Remove the user_id in the Cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # As the page loads, it reads the cookie and determine the current user
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


## Handlers for each page

# It displays the front the page and lists all the blog posts
class FrontPage(Handler):
    def get(self):
        posts = db.GqlQuery("Select * From Post")
        self.render('front.html', posts = posts)

# It displays one certain blog posts
class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("single-post.html", post = post)


# It displays the form that creates a new post
class NewPostPage(Handler):
    # asks the user to login if he/she hasn't done so
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    # Post method for the form
    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject = subject, content = content)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


# Below 3 functions help validify the enterd username, email, and passwords
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# It displays the Sign Up Page
class SignupPage(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


# It displays the login page
class LoginPage(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)


# It implements the logout function
class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', FrontPage),
    ('/login', LoginPage),
    ('/signup', SignupPage),
    ('/logout', LogoutPage),
    ('/newpost', NewPostPage),
    ('/([0-9]+)', PostPage)

], debug=True)



#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#