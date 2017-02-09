import os
import webapp2
import jinja2
import codecs
import re
import hashlib
import hmac
import random
from string import letters
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

secret = 'RONSsecretWorD'

#default functions we use


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def blog_key(name='default'):
    return db.Key.from_path('Blog', name)

#cookies

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# make salt & password for to secure the password


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(''.join([name, pw, salt])).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# get the key from User table


def users_key(group='default'):
    return db.Key.from_path('users', group)

# define what a valid username is
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')


def valid_username(username):
    return username and USER_RE.match(username)

# define what a valid password is
PASS_RE = re.compile(r'^.{3,20}$')


def valid_password(password):
    return password and USER_RE.match(password)


#Main handlers (we got during course)

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # securely set a cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # read the cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # set a cookie when the user logs in
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # reset the cookie when the user logs out
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # get the user from secure cookie when we initialize pages
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#User table

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

#Blog table

class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User,
                                required=True,
                                collection_name="blogs")

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post=self)

#Likes table


class Like(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    # get number of likes for a blog id
    @classmethod
    def by_blog_id(cls, blog_id):
        l = Like.all().filter('post =', blog_id)
        return l.count()

    # get number of likes for a blog and user id
    @classmethod
    def check_like(cls, blog_id, user_id):
        cl = Like.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cl.count()


#unlike table
class Unlike(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_blog_id(cls, blog_id):
        ul = Unlike.all().filter('post =', blog_id)
        return ul.count()


    @classmethod
    def check_unlike(cls, blog_id, user_id):
        cul = Unlike.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cul.count()

#comments table

class Comment(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    @classmethod
    def count_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id)
        return c.count()

    @classmethod
    def all_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id).order('created')
        return c

#main front page
class MainPage(Handler):

    def get(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        if blogs:
            self.render("blogs.html", blogs=blogs)

#New posts
class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if self.user:

            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')
            user_id = User.by_name(self.user.name)

            if subject and content:
                a = Blog(
                    parent=blog_key(),
                    subject=subject,
                    content=content,
                    user=user_id)
                a.put()
                self.redirect('/post/%s' % str(a.key().id()))

            else:
                post_error = "Please enter a subject and the blog content"
                self.render(
                    "newpost.html",
                    subject=subject,
                    content=content,
                    post_error=post_error)

        else:
            self.redirect("/login")


#The post individual page
class PostPage(Handler):

    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        post_comments = Comment.all_by_blog_id(post)
        comments_count = Comment.count_by_blog_id(post)

        self.render(
            "post.html",
            post=post,
            likes=likes,
            unlikes=unlikes,
            post_comments=post_comments,
            comments_count=comments_count)

    def post(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)
        user_id = User.by_name(self.user.name)
        comments_count = Comment.count_by_blog_id(post)
        post_comments = Comment.all_by_blog_id(post)
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        previously_liked = Like.check_like(post, user_id)
        previously_unliked = Unlike.check_unlike(post, user_id)

        if self.user:
            if self.request.get("like"):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_liked == 0:
                        l = Like(
                            post=post, user=User.by_name(
                                self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    else:
                        error = "You  already liked this post"
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comments_count=comments_count,
                            post_comments=post_comments)

                else:
                    error = "You cannot like your own "
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comments_count=comments_count,
                        post_comments=post_comments)
            if self.request.get("unlike"):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_unliked == 0:

                        ul = Unlike(
                            post=post, user=User.by_name(
                                self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))

                    else:
                        error = "You  already unliked this "
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comments_count=comments_count,
                            post_comments=post_comments)

                else:
                    error = "You cannot unlike your own "
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comments_count=comments_count,
                        post_comments=post_comments)
            if self.request.get("add_comment"):
                comment_text = self.request.get("comment_text")
                if comment_text:
                    c = Comment(
                        post=post, user=User.by_name(
                            self.user.name), text=comment_text)
                    c.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                else:
                    comment_error = "Please enter a comment in the text area to post"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        comment_error=comment_error)
            if self.request.get("edit"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    self.redirect('/edit/%s' % str(post.key().id()))
                else:
                    error = "You cannot edit other user's posts"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        error=error)
            if self.request.get("delete"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    db.delete(key)
                    time.sleep(0.1)
                    self.redirect('/')
                else:
                    error = "You cannot delete other user's posts"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        error=error)
        else:
            self.redirect("/login")

#Delet a comment

class DeleteComment(Handler):

    def get(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            if comment.user.name == self.user.name:
                db.delete(comment)
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            else:
                self.write("You cannot delete other people comments")
        else:
            self.write("Comment deleted")

#Edit a comment

class EditComment(Handler):

    def get(self, post_id, comment_id):
        post = Blog.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            if comment.user.name == self.user.name:
                self.render("editcomment.html", comment_text=comment.text)

            else:
                error = "You cannot edit other users' comments'"
                self.render("editcomment.html", edit_error=error)

        else:
            error = "This comment no longer exists"
            self.render("editcomment.html", edit_error=error)

    def post(self, post_id, comment_id):
        if self.request.get("update_comment"):
            comment = Comment.get_by_id(int(comment_id))
            if comment.user.name == self.user.name:
                comment.text = self.request.get('comment_text')
                comment.put()
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            else:
                error = "You cannot edit other users' comments'"
                self.render(
                    "editcomment.html",
                    comment_text=comment.text,
                    edit_error=error)
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post_id))

#post edit
class EditPost(Handler):

    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                self.render("editpost.html", post=post)

            else:
                self.response.out.write("You cannot edit other user's posts")
        else:
            self.redirect("/login")

    def post(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        if self.request.get("update"):

            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')

            if post.user.key().id() == User.by_name(self.user.name).key().id():
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                else:
                    post_error = "Please enter a subject and the blog content"
                    self.render(
                        "editpost.html",
                        subject=subject,
                        content=content,
                        post_error=post_error)
            else:
                self.response.out.write("You cannot edit other user's posts")
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post.key().id()))

#Sign up functions (based on course)


class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if have_error:
            self.render("signup.html", **params)

        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

#Register

class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            error = 'That user already exists.'
            self.render('signup.html', error_username=error)

        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

#welcome page

class Welcome(Handler):

    def get(self):
        if self.user:
            self.render("welcome.html", username=self.user.name)
        else:
            self.redirect("/login")

#Log in

class Login(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')

        else:
            error = 'Invalid login'
            self.render('login.html', error=error)

#Log out


class Logout(Handler):

    def get(self):
        if self.user:
            self.logout()
            self.redirect("/signup")
        else:
            error = 'You need to be logged in to be able to log out. Please log in.'
            self.render('login.html', error=error)

#The main webapp

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', NewPost),
    ('/post/([0-9]+)', PostPage),
    ('/login', Login),
    ('/logout', Logout),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/edit/([0-9]+)', EditPost),
    ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
    ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
], debug=True)
