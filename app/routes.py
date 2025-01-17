from flask import render_template, redirect, request, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from app import app, db
from app.models import User, Post, Category, Like, Comment
from app.helpers import login_required, error
from flask import make_response



@app.after_request
def add_header(response):
    response.cache_control.no_store = True
    return response

categorieslist = [
    {'id': 1, 'name': 'Programming Languages'},
    {'id': 2, 'name': 'Cybersecurity'},
    {'id': 3, 'name': 'Database Management'},
    {'id': 4, 'name': 'Computer Science Theory'},
    {'id': 5, 'name': 'Web Development'},
    {'id': 6, 'name': 'Career Development'},
    {'id': 7, 'name': 'Motivation & Mindset'},
    {'id': 8, 'name': 'Game Development'},
    {'id': 9, 'name': 'Software Development'},
    {'id': 10, 'name': 'Learning Resources'},
    {'id': 11, 'name': 'Blockchain & Cryptocurrencies'},
    {'id': 12, 'name': 'Community & Support'}
]

@app.context_processor
def inject_user_status():
    # Check if the user is logged in based on session data
    return {"is_authenticated": "user_id" in session}

@app.route("/")
# @login_required
def index():
    return render_template("homepage.html")

@app.route("/allposts")
@login_required
def allposts():
    # is_authenticated = "user_id" in session
    user_id = session.get("user_id")
    search_query = request.args.get("q")

    page = request.args.get("page", 1, type=int)
    per_page = 5
    if search_query:
        # posts = Post.query.filter(Post.title.ilike(f"%{search_query}%")).order_by(Post.date_posted.desc()).all()
        posts = Post.query.filter(Post.title.ilike(f"%{search_query}%")).order_by(Post.date_posted.desc()).paginate(page=page, per_page=per_page)
    else:
        # posts = Post.query.order_by(Post.date_posted.desc()).all()
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=per_page)

    for post in posts.items:
        # Set user_liked if user is logged in and has liked this post
        if user_id:
            post.user_liked = Like.query.filter_by(user_id=user_id, post_id=post.id).first() is not None
        else:
            post.user_liked = False
            
    if not posts.items:
        flash("No posts found!", "info")
        return render_template("noposts.html")
    return render_template("index.html", posts=posts, user_id=user_id)



@app.route('/like/<int:post_id>', methods=['POST'])
def like_post(post_id):

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "You need to log in to like a post."}), 401

    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        liked = False
    else:
        like = Like(user_id=user_id, post_id=post_id)
        db.session.add(like)
        liked = True

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while processing your request."}), 500

    return jsonify({"liked": liked, "likes_count": post.likes.count()})


# @app.route('/like/<int:post_id>', methods=['POST'])
# def like_post(post_id):

#     user_id = session.get("user_id")

#     if not user_id:
#         flash("You need to log in to like a post.", "error")
#         return redirect("/login")

#     post = Post.query.get_or_404(post_id)
#     existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    
#     if existing_like:
#         db.session.delete(existing_like)
#     else:
#         like = Like(user_id=user_id, post_id=post_id)
#         db.session.add(like)
    
#     db.session.commit()
#     return redirect(request.referrer or "/allposts")


@app.route('/comment/<int:post_id>', methods=['POST'])
def comment_post(post_id):

    user_id = session.get("user_id")

    if not user_id:
        flash("You need to log in to comment on a post.", "error")
        return redirect("/login")
    
    post = Post.query.get_or_404(post_id)
    comment_content = request.form.get('commentposted')

    # White space check
    if not comment_content.strip():
        flash("Comment cannot be empty", "error")
        return redirect(request.referrer or "/allposts")
    
    # If request.form.get('commentposted') is None, it could lead to unexpected issues.
    if not comment_content:
        flash("Comment cannot be empty", "error")
        return redirect(request.referrer or "/allposts")

    new_comment = Comment(comment_content=comment_content, user_id=user_id, post_id=post_id)
    db.session.add(new_comment)
    db.session.commit()
    return redirect(request.referrer or "/allposts")


@app.route("/login", methods=["GET", "POST"])
def login():
    # session.clear()
    if "user_id" in session:
        session.clear()

    if request.method == "POST":
        username = request.form.get("name")
        password = request.form.get("password")

        if not username or not password:
            flash("Enter Username and Password!", "danger")
            return redirect("/login")
        
        username = username.lower()        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.passwordhash, password):
            flash("Username or Password Incorrect!", "danger")
            return redirect("/login")
        
        session["user_id"] = user.id
        # flash("Logged in!", "success")
        return redirect("/create")
    return render_template("login.html")
    
    
@app.route("/logout", methods=["GET", "POST"])
def logout():

    # session.clear()
    # flash("Logged Out!", "success")
    session.pop("user_id", None)
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    # session.clear()
    if "user_id" in session:
        session.clear()

    if request.method == "POST":
        username = request.form.get("name")
        password = request.form.get("password")
        confirmPassword = request.form.get("confirmpasswordlb")

        if not username or not password or not confirmPassword:
            flash("Oops! You did not input a name or password.", "danger")
            return redirect("/signup")
            
        
        if password != confirmPassword:
            flash("Oops! Your passwords don't match!", "danger")
            return redirect("/signup")

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect("/signup")

        username = username.lower()  # Ensure username is case-insensitively unique

        existingUsername = User.query.filter_by(username=username).first()
        if existingUsername:
            flash(f"Oops! {username} has been taken! Retry another!", "danger")
            return redirect("/signup")

        generatedPassword = generate_password_hash(password)
        new_user = User(username=username, passwordhash=generatedPassword)
        db.session.add(new_user)

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"An unexpected  error occurred: {str(e)}", 'danger')
            return redirect("/signup")

        session["user_id"] = new_user.id
        flash("Registration successful!", "success")
        return redirect("/create")

    return render_template("signup.html")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    user_id = session.get("user_id")  

    if request.method == "POST":
        post_title = request.form.get("posttitle")
        post_content = request.form.get("postcontent")
        post_category = request.form.get("category")

        if not post_title or not post_content or not post_category:
            flash("Please fill in all fields!", "danger")
            return redirect("/create")

        category = Category.query.filter_by(name=post_category).first()
        if not category:
            # Create and save the new category if it doesn't exist
            category = Category(name=post_category)
            db.session.add(category)
            db.session.commit()

        category_id = category.id

        creator = User.query.get(user_id)
        if not creator:
            flash("Oops! An error occurred while fetching your details!", "danger")
            return redirect("/create")
  
        new_post = Post(
            title=post_title,
            content=post_content,
            creator_id=user_id,
            category_id=category_id,
            creator_name=creator.username,
            category_name=category.name
        )
        db.session.add(new_post)
        db.session.commit()

        flash("Post created successfully!", "success")
        return redirect("/allposts")
    return render_template("create.html", categorieslist=categorieslist)




@app.route("/category", methods=["GET", "POST"])
@login_required
def category():
    categories = Category.query.all() 

    if request.method == "POST":
        category_name = request.form.get("category")  

        if not category_name:
            flash("Please select a category!", "danger")
            return redirect("/category")
        
        posts = Post.query.filter_by(category_name=category_name).all() 

        return render_template("categories.html", category_name=category_name, posts=posts)
    return render_template("category.html", categories=categories)


@app.route("/myposts")
@login_required
def myposts():
    user_id = session["user_id"]

    page = request.args.get("page", 1, type=int)
    per_page = 5

    my_posts = Post.query.filter_by(creator_id=user_id).order_by(Post.date_posted.desc()).paginate(page=page, per_page=per_page)
    # my_posts = Post.query.filter_by(creator_id=user_id).order_by(Post.date_posted.desc()).all()
    # if not my_posts.items:
    #     flash("Sorry! You have no posts available!", "danger")
    return render_template("myposts.html", posts=my_posts)


@app.route("/creators")
def creators():
    users = User.query.all()
    current_user = session.get("user_id")
    return render_template("creators.html", users=users, current_user=current_user)


@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.creator_id != session["user_id"]:
        flash("You are not authorized to edit this post!", "danger")
        return redirect("/allposts")

    if request.method == "POST":
        post_title = request.form.get("posttitle")
        post_content = request.form.get("postcontent")

        if not post_title or not post_content:
            flash("Please fill in all fields!", "danger")
            return redirect(f"/edit/{post_id}")

        # Update the post
        post.title = post_title
        post.content = post_content
        db.session.commit()

        flash("Post updated successfully!", "success")
        return redirect("/myposts")
    return render_template("edit.html", post=post)


@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    user_id = session.get("user_id")

    if not post or post.creator_id != user_id:
        flash("Unauthorized access!", "danger")
        return redirect("/myposts")

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "success")
    return redirect("/myposts")


@app.route("/progress")
def progress():
    return render_template("progress.html")
