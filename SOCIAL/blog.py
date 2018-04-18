import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'temp')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'Blog'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Base class for all the handlers!

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # check whether logged in user has a posts or not.
    def users_post(self, user, post):
        return int(post.user_id) == user.key().id()

    # check whether user logged in or not.
    def user_loggedin(self, user):
        if not user:
            self.redirect('/login')
            return
        else:
            return True

    # check if there is any post or not.
    def post_is_there(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        return post

    # check whether there is any comment or not.
    def comment_is_there(self, comm_id):
        key = db.Key.from_path('Comment', int(comm_id))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return
        return comment

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# The user Model
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    profile_pic = db.BlobProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, profile_pic, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    profile_pic = profile_pic,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# The Post Model.
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)                 #used text prpoperty since its word limit ids more than 500 characters.
    created = db.DateTimeProperty(auto_now_add = True)         # time when the blog was created.
    user_id = db.StringProperty()
    last_modified = db.DateTimeProperty(auto_now = True)       # every time something is updated it takes that time.
    like = db.StringProperty(default = "0")
    dislike = db.StringProperty(default = "0")
    username = db.StringProperty(required = True)
    count_comment = db.StringProperty(default = "0")
    category = db.StringProperty(required = True)
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

# The Comment Model.
class Comment(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    holder = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    
    def get_UserName(self):
        user = User.by_id(self.user_id)
        return user.name

# Render the blog front page.
class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post order by like desc")
        self.render('front.html', posts = posts)

class Search(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('search_result.html', posts = posts)
####################################################################################################
class UserPost(BlogHandler):
    def get(self):
        if self.user_loggedin(self.user):
                posts = greetings = Post.all().order('-created')
                self.render("mypost.html", posts=posts)
                return

class UsePost(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        user =  db.GqlQuery("SELECT * from User")
        self.render("userpost.html", posts=posts,user = user)
        return

# To lookup a particular post.
class PostPage(BlogHandler):

    def get(self, post_id):                   #post_id acts as key for the search.
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class ParPage(BlogHandler):

    def get(self, post_id):                   #post_id acts as key for the search.
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("ek_blog.html", post = post)

class ParaPage(BlogHandler):

    def get(self, post_id):                   #post_id acts as key for the search.
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        if post:
            postComment = Comment.all().filter('post_id =', post_id).order('-created')
            self.render("do_blog.html", post = post, comments = postComment)
class Profile(BlogHandler):

    def get(self,u_id):
        profile_pic = User.all().filter('name =', u_id)
        self.render("view_profile.html", profile_pic = profile_pic)

# Post creation handler.
class NewPost(BlogHandler):

    def get(self):
        if self.user_loggedin(self.user):
            self.render("newpost.html")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        category = self.request.get('category')
        subject = self.request.get('subject')
        content = self.request.get('content')
        username = self.user.name

        if subject and content and category:
            post = Post(parent=blog_key(), subject=subject, content=content, username=username,category=category)
            post.user_id = str(self.user.key().id())
            post.put()
            postComment = Comment.all().filter('post_id =', post.key().id())
            self.render("permalink.html", post=post, comments=postComment)
        else:
            error = "Enter the subject and content!"
            self.render(
                "newpost.html", subject=subject, content=content,category=category,
                error=error)


class Upload(BlogHandler):

    def get(self):
        if self.user_loggedin(self.user):
            self.render("upload.html")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent=blog_key(), subject=subject, content=content)
            post.user_id = str(self.user.key().id())
            post.put()
            postComment = Comment.all().filter('post_id =', post.key().id())
            self.render("permalink.html", post=post, comments=postComment)
        else:
            error = "Enter the subject and content!"
            self.render(
                "newpost.html", subject=subject, content=content,
                error=error)

# The Like Model.
class LikeModel(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()
    username = db.StringProperty()
    def get_UserName(self):
        user = User.by_id(self.user_id)
	return user.name


# Handler for liking a post.
class LikePost(BlogHandler):

    def get(self, p_Id):
        if self.user_loggedin(self.user):
            post = self.post_is_there(p_Id)
            if post:
                postComment = Comment.all().filter('post_id =', p_Id)
                if self.users_post(self.user, post):
                    self.render(
                        "permalink.html", post=post,
                        error="User cannot like his/her own post!",
                        comments=postComment)
                    return
		
                like = LikeModel.all()
                like.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', p_Id)
		if like.get():
                    self.render(
                        "permalink.html", post=post,
                        error="This post is already liked by you.",
                        comments=postComment)
                    return
                
                liked = LikeModel(user_id=str(self.user.key().id()), post_id=p_Id, username = self.user.name)
                liked.put()

	        lik = False
                likes = DislikeModel.all().filter('post_id =', p_Id)
                if self.user:
                    for like in likes:
                        if self.user.name == like.username:
                            lik = True
			    s = like.username
                            like.delete()
                            break
	
		if int(post.dislike) == 0 and lik is False:
  
		    post.like = str(int(post.like) + 1)
			
		else:
		    if lik is True:	
	                post.dislike = str(int(post.dislike) - 1)
		        post.like = str(int(post.like) + 1)
		    else:
			post.like = str(int(post.like) + 1)
		post.put()
		self.render("permalink.html", post=post, comments=postComment)

# The Dislike Model.
class DislikeModel(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()
    username = db.StringProperty()
    def get_UserName(self):
        user = User.by_id(self.user_id)
	return user.name


# Handler for disliking a post.
class DislikePost(BlogHandler):

    def get(self, p_Id):
        if self.user_loggedin(self.user):
            post = self.post_is_there(p_Id)
            if post:
                postComment = Comment.all().filter('post_id =', p_Id)
                if self.users_post(self.user, post):
                    return self.render(
                        "permalink.html",
                        post=post,
                        error="User cannot dislike his/her own post!",
                        comments=postComment)

                dislike = DislikeModel.all()
                dislike.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', p_Id)
		if dislike.get():
                    self.render(
                        "permalink.html", post=post,
                        error="This post is already disliked by you.",
                        comments=postComment)
                    return
                

                liked = DislikeModel(user_id=str(self.user.key().id()), post_id=p_Id, username = self.user.name)
		liked.put()
	        lik = False
                likes = LikeModel.all().filter('post_id =', p_Id)
                if self.user:
                    for like in likes:
                        if self.user.name == like.username:
                            lik = True
			    s = like.username
                            like.delete()
                            break
	
		
		if int(post.dislike) == 0 and lik is False:
  
		    post.dislike = str(int(post.dislike) + 1)
			
		else:
		    if lik is True and int(post.dislike) == 0:	
	                post.dislike = str(int(post.dislike) + 1)
		        post.like = str(int(post.like) - 1)
		    else:
			if lik is True:
			    post.dislike = str(int(post.dislike) + 1)
		            post.like = str(int(post.like) - 1)
			else:
			    post.dislike = str(int(post.dislike) + 1)
		post.put()
		
		self.render("permalink.html", post=post, comments=postComment)
		    
                   	    
		            
		        
# Comment mainpage handler.
class MainPageComm(BlogHandler):

    def post(self, p_Id):
        if self.user_loggedin(self.user):
            recentComment = self.request.get("comment")
            post = self.post_is_there(p_Id)
            if not recentComment:
                self.render(
                    "permalink.html", post=post,
                    content=recentComment,
                    error="Please, Enter a valid comment!")
                return
	    
            post.count_comment = str(int(post.count_comment) + 1) 
            # create a new row "comments"and update the Comment entity
            b = Comment(user_id=str(self.user.key().id()),
                        post_id=p_Id, comment=recentComment,
                        holder=self.user.name)
            b.put()
            post.put()
            if p_Id:
                postComment = Comment.all().filter('post_id =', p_Id).order('-created')
                self.render("permalink.html", post=post, comments=postComment)

# Comment creation handler.
class PostComment(BlogHandler):

    def get(self, p_Id):
        if self.user_loggedin(self.user):
            post = self.post_is_there(p_Id)
            if post:
                postComment = Comment.all().filter('post_id =', p_Id).order('-created')
                self.render("permalink.html", post=post, comments=postComment)

# Comment deletion handler.
class DeleteComment(BlogHandler):

    def get(self, c_Id):
        if not self.user_loggedin(self.user):
            return

        com = self.comment_is_there(c_Id)
        if not com:
            return

        p_Id = com.post_id
        post = self.post_is_there(p_Id)
        if not post:
            return

        if int(com.user_id) == self.user.key().id():
            com.delete()
            post.count_comment=str(int(post.count_comment)-1)
            post.put() 
            postComment = Comment.all().filter(
                          'post_id =', p_Id).order('-created')
            self.render("permalink.html", post=post, comments=postComment)
        else:
            postComment = Comment.all().filter(
                          'post_id =', p_Id).order('-created')
            self.render(
                    "permalink.html",
                     post=post,
                     error="user can only delete his/her own comment!",
                     comments=postComment)

# Comment edits handler.
class EditComment(BlogHandler):

    def get(self, c_Id):
        if not self.user_loggedin(self.user):
            return

        com = self.comment_is_there(c_Id)
        if not com:
            return

        post = self.post_is_there(com.post_id)
        if not post:
            return
        postComment = Comment.all().filter('post_id =', com.post_id).order('-created')

        if int(com.user_id) == self.user.key().id():
            self.render("editcomment.html",
                         post=post,
                         content=com.comment,
                         comment=com)
        else:
            self.render("permalink.html",
                         post=post,
                         error="User can only edit his/her own comment!",
                         comments=postComment)

    def post(self, c_Id):
        if not self.user_loggedin(self.user):
            return

        com = self.comment_is_there(c_Id)
        if not com:
            return

	post = self.post_is_there(com.post_id)
        if not post:
            return

        newComment = self.request.get("comment")
        if not newComment:
            error = "Please, enter valid content !"
            self.render("editcomment.html", post=post, content=newComment, error=error, comment=com)
            return

        # update the row and the Comment entity
        key = db.Key.from_path('Comment', int(c_Id))
        com = db.get(key)
        com.comment = newComment
        com.put()

        postComment = Comment.all().filter('post_id =', com.post_id).order('-created')
        self.render("permalink.html", post=post, comments=postComment)

# Post deletion handler.
class DeletePost(BlogHandler):

    def get(self, p_Id):
        if self.user_loggedin(self.user):
            post = self.post_is_there(p_Id)
            if post:
                if self.users_post(self.user, post):
                    post.delete()
                    posts = greetings = Post.all().order('-created')
                    self.redirect('/blog/')
                else:
                    postComment = Comment.all().filter('post_id =', p_Id)
                    self.render(
                        "permalink.html", post=post,
                        error="User can only delete his/her own post.",
                        comments=postComment)
        else:
           self.redirect("/login")

# Post edits handler.
class EditPost(BlogHandler):

    def get(self, p_Id):
        if self.user_loggedin(self.user):
            post = self.post_is_there(p_Id)
            if post:
                if self.users_post(self.user, post):
                    self.render(
                        "editpost.html", subject=post.subject,
                        content=post.content)
                else:
                    postComment = Comment.all().filter('post_id =', p_Id)
                    self.render(
                        "permalink.html", post=post,
                        error="User can only edit his/her own post.",
   			comments=postComment)
        else:
           self.redirect("/login")

    def post(self, p_Id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        post = self.post_is_there(p_Id)
        if not post:
            return

        if not self.users_post(self.user, post):
            postComment = Comment.all().filter('post_id =', p_Id)
            self.render("permalink.html", post=post,
                        error="User can only edit his/her own post.",
                        comments=postComment)
        elif subject and content:
            post.subject = subject
            post.content = content
            post.put()
            postComment = Comment.all().filter('post_id =', p_Id)
            self.render("permalink.html", post=post, comments=postComment)
        else:
            error = "Enter the subject and content!"
            self.render(
	    "editpost.html", subject=subject, content=content, error=error)

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


# User account creation handler.
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.profile_pic = self.request.get('profile_pic')
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
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


# User account registration handler.
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist.
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.profile_pic, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


# User account login handler.
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


# User account logout handler.
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')
class ChatModel(db.Model):
    from_username = db.StringProperty(required=True)
    to_username = db.StringProperty(required=True)
    chat = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
	

            
class Chatting(BlogHandler):
    def get(self,u_Id):
	if self.user_loggedin(self.user):
	    
            users = db.GqlQuery("SELECT * FROM User")
	    postChat = db.GqlQuery("SELECT * FROM ChatModel order by created")
            
            self.render("chatting.html",u = u_Id, ch=postChat, users = users)
            return

    def post(self, u_Id):
        if self.user_loggedin(self.user):
            recentChat = self.request.get("chat")
            
            if not recentChat:
	        error="Please, Enter a valid message!"
                self.render(
                "chatting_error.html", 
                error=error)
                return
            
            
            b = ChatModel(from_username=self.user.name,
            to_username=u_Id, chat=recentChat)
            b.put()
            self.redirect('/blog/chat/'+u_Id)
            return
           
                             
                 
class Chat(BlogHandler):
    def get(self):
	if self.user_loggedin(self.user):
	    self.redirect('/blog/chat/'+self.user.name)
            return	     

class ShowUsersPost(BlogHandler):

    def get(self, u_Id):
	
        posts = Post.all().filter('user_id =', u_Id)
	
        
        self.render("show_users_post.html", posts=posts)

class MostLikedPost(BlogHandler):

    def get(self):
	
        post = db.GqlQuery("SELECT * FROM Post order by like desc limit 1")
	
        
        self.render("most_liked_post.html", post=post)

class TagsPost(BlogHandler):
    def get(self,c_id):
        posts = Post.all()
	self.render("tags.html", post = posts,c = c_id)

#url mapping
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/search', Search),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/ekblog/([0-9]+)', ParPage),
                               ('/blog/doblog/([0-9]+)', ParaPage),#[0-9] is passed as the id for searching a particular post
                               ('/blog/newpost', NewPost),
                               ('/blog/userpost', UserPost),
                               ('/blog/mostlikedposts', MostLikedPost),
                               ('/blog/usepost', UsePost),
 			       ('/blog/users/([0-9]+)', ShowUsersPost),
                               ('/blog/view_profile/([0-9||A-Z||a-z]+)', Profile),
			       ('/blog/newpost/upload', Upload),
			       ('/blog/chat', Chat),
		               
   			       ('/blog/chat/([a-z||A-Z||0-9]+)',Chatting),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/dislike/([0-9]+)', DislikePost),
                               ('/blog/commentmainpage/([0-9]+)', MainPageComm),
                               ('/blog/postcomment/([0-9]+)', PostComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
			       ('/blog/tagsPost/([0-9||A-Z||a-z]+)', TagsPost),
                               ],
                              debug=True)
