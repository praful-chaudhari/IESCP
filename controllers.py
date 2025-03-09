from app import app
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, current_user
from models import db, User, Campaign, Ad_Request
from werkzeug.security import generate_password_hash, check_password_hash
from config import login_manager
from functools import wraps
import json
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.user_type != "admin":
            flash("You do not have permission to access this page.", category="danger")
            if current_user.user_type == "influencer":
                return redirect(url_for("influencer_dashboard"))
            elif current_user.user_type == "sponsor":
                return redirect(url_for("sponsor_dashboard"))
        return func(*args, **kwargs)
    return wrapper

def sponsor_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.user_type != "sponsor":
            flash("You do not have permission to access this page.", category="danger")
            if current_user.user_type == "admin":
                return redirect(url_for("admin_dashboard"))
            elif current_user.user_type == "influencer":
                return redirect(url_for("influencer_dashboard"))
        return func(*args, **kwargs)
    return wrapper

def influencer_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.user_type != "influencer":
            flash("You do not have permission to access this page.", category="danger")
            if current_user.user_type == "admin":
                return redirect(url_for("admin_dashboard"))
            elif current_user.user_type == "sponsor":
                return redirect(url_for("sponsor_dashboard"))
        return func(*args, **kwargs)
    return wrapper

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    flash("Please login to access this page.", category="danger")
    return redirect(url_for("user_login"))

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        if not username:
            flash("Username is required.", category="danger")
            return render_template("admin_login.html", user="")
        if not password:
            flash("Password is required.", category="danger")
            return render_template("admin_login.html", user="")
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", category="danger")
            return render_template("admin_login.html", user="")
        if user.user_type != "admin":
            flash("User can't login with admin login.", category="danger")
            return redirect(url_for("user_login"))
        login_user(user, remember=True)
        flash("Logged in successfully.", category="success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html", user="")

@app.route("/")
@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        if not username:
            flash("Username is required.", category="danger")
            return render_template("user_login.html", user="")
        if not password:
            flash("Password is required.", category="danger")
            return render_template("user_login.html", user="")
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", category="danger")
            return redirect(url_for("user_login"))
        if user.flagged:
            flash("Your account is flagged.", category="danger")
            return redirect(url_for("flagged_user"))
        if user.user_type == "admin":
            flash("Admin can't login with user login.", category="danger")
            return redirect(url_for("admin_login", user=""))
        login_user(user, remember=True)
        flash("Logged in successfully.", category="success")
        if user.user_type == "influencer":
            return redirect(url_for("influencer_dashboard"))
        elif user.user_type == "sponsor":
            return redirect(url_for("sponsor_dashboard"))
    return render_template("user_login.html", user="")

@app.route("/flagged_user")
def flagged_user():
    return render_template("flagged_user.html", user="")

@app.route("/influencer_register", methods=["GET", "POST"])
def influencer_register():
    if request.method == 'POST':
        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]
        cpassword = request.form["cpassword"]
        platforms = request.form.getlist('platforms')
        category = request.form["category"]
        niche = request.form["niche"]
        follower_count = request.form["subscribers"]
        if not username:
            flash("Username is required.", category="danger")
            return render_template("influencer_register.html")
        if not password or not cpassword:
            flash("Password is required.", category="danger")
            return render_template("influencer_register.html")
        if password != cpassword:
            flash("Passwords do not match.", category="danger")
            return render_template("influencer_register.html")
        if platforms == []:
            flash("Atleast one platform should be selected", category="danger")
            return render_template("influencer_register.html")
        if not category:
            flash("Category is required.", category="danger")
            return render_template("influencer_register.html")
        if not niche:
            flash("Niche is required.", category="danger")
            return render_template("influencer_register.html")
        if not follower_count:
            flash("Subscribers/Followers is required.", category="danger")
            return render_template("influencer_register.html")
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists.", category="danger")
            return render_template("influencer_register.html")
        user = User(name=name, username=username, password_hash=generate_password_hash(password), user_type="influencer", category=category, niche=niche, follower_count=follower_count, platforms=json.dumps(platforms))
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully.", category="success")
        return redirect(url_for("user_login"))
    return render_template("influencer_register.html", user="")

@app.route("/sponsor_register", methods=["GET", "POST"])
def sponsor_register():
    if request.method == 'POST':
        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]
        cpassword = request.form["cpassword"]
        industry = request.form["industry"]
        budget = request.form["budget"]
        if not username:
            flash("Username is required.", category="danger")
            return render_template("sponsor_register.html")
        if not password or not cpassword:
            flash("Password is required.", category="danger")
            return render_template("sponsor_register.html")
        if password != cpassword:
            flash("Passwords do not match.", category="danger")
            return render_template("sponsor_register.html")
        if not industry:
            flash("Industry is required.", category="danger")
            return render_template("sponsor_register.html")
        if not budget:
            flash("Budget is required.", category="danger")
            return render_template("sponsor_register.html")
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists.", category="danger")
            return render_template("sponsor_register.html")
        if password != cpassword:
            flash("Passwords do not match.", category="danger")
            return render_template("sponsor_register.html")
        user = User(name=name, username=username, password_hash=generate_password_hash(password), industry=industry, budget=budget, user_type="sponsor")
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully.", category="success")
        return redirect(url_for("user_login"))
    return render_template("sponsor_register.html", user="")

@app.route("/logout")
@login_required
def logout():
    if current_user.user_type == "admin":
        logout_user()
        flash("Logged out successfully.", category="success")
        return redirect(url_for("admin_login"))
    logout_user()
    flash("Logged out successfully.", category="success")
    return redirect(url_for("user_login"))

@app.route("/admin/dashboard/all_sponsors")
@app.route("/admin/dashboard", methods=["GET", "POST"])
@login_required
@admin_required
def admin_dashboard():
    if request.method == "POST":
        search_type = request.form["search_type"]
        search_query = request.form["search"]
        if search_type == "":
            flash("Please select search type.", category="danger")
            return redirect(url_for("admin_dashboard"))
        if search_query == "":
            flash("Please enter search.", category="danger")
            return redirect(url_for("admin_dashboard"))
        if search_type == "sname":
            query = User.query.filter(User.name.ilike(f'%{search_query}%'))
            if query:
                query = query.filter_by(user_type="sponsor")
            flagged_results = query.filter(User.flagged==1).all()
            unflagged_results = query.filter(User.flagged==0).all()
            return render_template("admin/all_sponsors.html", user=current_user, flagged_sponsors=flagged_results, unflagged_sponsors=unflagged_results)
        if search_type == "maxbudget":
            try:
                maxbudget = int(search_query)
            except Exception as e:
                flash("Invalid budget.", category="danger")
                return redirect(url_for("admin_dashboard"))
            if maxbudget < 0:
                flash("Invalid budget.", category="danger")
                return redirect(url_for("admin_dashboard"))
            query = User.query.filter(User.budget <= maxbudget)
            if query:
                query.filter_by(user_type="sponsor")
            flagged_results = query.filter(User.flagged==1).all()
            unflagged_results = query.filter(User.flagged==0).all()
            return render_template("admin/all_sponsors.html", user=current_user, flagged_sponsors=flagged_results, unflagged_sponsors=unflagged_results)
        if search_type == "minbudget":
            try:
                minbudget = int(search_query)
            except Exception as e:
                flash("Invalid budget.", category="danger")
                return redirect(url_for("admin_dashboard"))
            if minbudget < 0:
                flash("Invalid budget.", category="danger")
                return redirect(url_for("admin_dashboard"))
            query = User.query.filter(User.budget >= minbudget)
            if query:
                query.filter_by(user_type="sponsor")
            flagged_results = query.filter(User.flagged==1).all()
            unflagged_results = query.filter(User.flagged==0).all()
            return render_template("admin/all_sponsors.html", user=current_user, flagged_sponsors=flagged_results, unflagged_sponsors=unflagged_results)
        if search_type == "industry":
            query = User.query.filter(User.industry.ilike(f'%{search_query}%'))
            if query:
                query = query.filter_by(user_type="sponsor")
            flagged_results = query.filter(User.flagged==1).all()
            unflagged_results = query.filter(User.flagged==0).all()
            return render_template("admin/all_sponsors.html", user=current_user, flagged_sponsors=flagged_results, unflagged_sponsors=unflagged_results)
        return redirect(url_for("admin_dashboard"))
    return render_template("admin/all_sponsors.html", user=current_user, unflagged_sponsors=User.query.filter(User.user_type=="sponsor", User.flagged==False).all(), flagged_sponsors=User.query.filter(User.user_type=="sponsor", User.flagged==True).all())

@app.route("/admin/dashboard/all_influencers", methods=["GET", "POST"])
@login_required
@admin_required
def all_influencers():
    if request.method == "POST":
        search_type = request.form["search_type"]
        search_string = request.form["search"]
        if search_type == "":
            flash("Please select search type.", category="danger")
            return redirect(url_for("all_influencers"))
        if search_type == "iname":
            query = User.query.filter(User.name.ilike(f'%{search_string}%'))
            if query:
                query = query.filter_by(user_type="influencer")
            unflagged_results = query.filter(User.flagged == 0).all()
            flagged_results = query.filter(User.flagged == 1).all()
            return render_template("admin/all_influencers.html", user=current_user, unflagged_influencers=unflagged_results, flagged_influencers=flagged_results)
        if search_type == "maxfollowers":
            try:
                maxfollowers = int(search_string)
            except Exception as e:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("all_influencers"))
            if maxfollowers < 0:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("all_influencers"))
            query = User.query.filter(User.follower_count <= maxfollowers)
            if query:
                query.filter_by(user_type="influencer")
            unflagged_results = query.filter(User.flagged == 0).all()
            flagged_results = query.filter(User.flagged == 1).all()
            return render_template("admin/all_influencers.html", user=current_user, unflagged_influencers=unflagged_results, flagged_influencers=flagged_results)
        if search_type == "minfollowers":
            try:
                minfollowers = int(search_string)
            except Exception as e:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("all_influencers"))
            if minfollowers < 0:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("all_influencers"))
            query = User.query.filter(User.follower_count >= minfollowers)
            if query:
                query.filter_by(user_type="influencer")
            unflagged_results = query.filter(User.flagged == 0).all()
            flagged_results = query.filter(User.flagged == 1).all()
            return render_template("admin/all_influencers.html", user=current_user, unflagged_influencers=unflagged_results, flagged_influencers=flagged_results)
        if search_type == "category":
            query = User.query.filter(User.category.ilike(f'%{search_string}%'))
            if query:
                query = query.filter_by(user_type="influencer")
            unflagged_results = query.filter(User.flagged == 0).all()
            flagged_results = query.filter(User.flagged == 1).all()
            return render_template("admin/all_influencers.html", user=current_user, unflagged_influencers=unflagged_results, flagged_influencers=flagged_results)
        if search_type == "niche":
            query = User.query.filter(User.niche.ilike(f'%{search_string}%'))
            if query:
                query = query.filter_by(user_type="influencer")
            unflagged_results = query.filter(User.flagged == 0).all()
            flagged_results = query.filter(User.flagged == 1).all()
            return render_template("admin/all_influencers.html", user=current_user, unflagged_influencers=unflagged_results, flagged_influencers=flagged_results)
        
    return render_template("admin/all_influencers.html", user=current_user, unflagged_influencers=User.query.filter(User.user_type=="influencer", User.flagged==0).all(), flagged_influencers=User.query.filter(User.user_type=="influencer", User.flagged==1).all())

@app.route("/admin/dashboard/view/user/<int:user_id>")
@login_required
@admin_required
def admin_view_user(user_id):
    user = User.query.get(user_id)
    if user.user_type == "sponsor":
        return render_template("admin/view_sponsor.html", user=current_user, sponsor=user)
    elif user.user_type == "influencer":
        platforms = json.loads(user.platforms)
        return render_template("admin/view_influencer.html", user=current_user, influencer=user, platforms=platforms)

@app.route("/admin/dashboard/all_campaigns", methods=["GET", "POST"])
@login_required
@admin_required
def all_campaigns():
    if request.method == "POST":
        search_type = request.form["search_type"]
        search_string = request.form["search"]
        if search_type == "":
            flash("Please select search type.", category="danger")
            return redirect(request.referrer)
        if search_type == "cname":
            query = Campaign.query.filter(Campaign.name.ilike(f'%{search_string}%'))
            if query:
                unflagged_results = query.filter(Campaign.flagged == 0).all()
                flagged_results = query.filter(Campaign.flagged == 1).all()
                return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
            flash("No search results.", category="danger")
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=[], flagged_campaigns=[])
        if search_type == "description":
            query = Campaign.query.filter(Campaign.description.ilike(f'%{search_string}%'))
            if query:
                unflagged_results = query.filter(Campaign.flagged == 0).all()
                flagged_results = query.filter(Campaign.flagged == 1).all()
                return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
            flash("No search results.", category="danger")
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=[], flagged_campaigns=[])
        if search_type == "goals":
            query = Campaign.query.filter(Campaign.goals.ilike(f'%{search_string}%'))
            if query:
                unflagged_results = query.filter(Campaign.flagged == 0).all()
                flagged_results = query.filter(Campaign.flagged == 1).all()
                return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
            flash("No search results.", category="danger")
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=[], flagged_campaigns=[])
        if search_type == "maxbudget":
            try:
                maxbudget = int(search_string)
            except Exception as e:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            if maxbudget < 0:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            query = Campaign.query.filter(Campaign.budget <= maxbudget)
            if query:
                flagged_results = query.filter(Campaign.flagged==1).all()
                unflagged_results = query.filter(Campaign.flagged==0).all()
                return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
            flash("No search results.", category="danger")
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=[], flagged_campaigns=[])
        if search_type == "minbudget":
            try:
                minbudget = int(search_string)
            except Exception as e:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            if minbudget < 0:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            query = Campaign.query.filter(Campaign.budget >= minbudget)
            if query:
                flagged_results = query.filter(Campaign.flagged==1).all()
                unflagged_results = query.filter(Campaign.flagged==0).all()
                return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
            flash("No search results.", category="danger")
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=[], flagged_campaigns=[])
        if search_type == "public":
            query = Campaign.query.filter_by(visibility="public")
            flagged_results = query.filter(Campaign.flagged==1).all()
            unflagged_results = query.filter(Campaign.flagged==0).all()
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
        if search_type == "private":
            query = Campaign.query.filter_by(visibility="private")
            flagged_results = query.filter(Campaign.flagged==1).all()
            unflagged_results = query.filter(Campaign.flagged==0).all()
            return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_results, flagged_campaigns=flagged_results)
    unflagged_campaigns = Campaign.query.filter_by(flagged=False).all()
    flagged_campaigns = Campaign.query.filter_by(flagged=True).all()
    return render_template("admin/all_campaigns.html", user=current_user, unflagged_campaigns=unflagged_campaigns, flagged_campaigns=flagged_campaigns)

@app.route("/admin/dashboard/view/campaign/<int:campaign_id>")
@login_required
@admin_required
def admin_view_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    sponsor = User.query.get(campaign.sponsor_id)
    return render_template("admin/view_campaign.html", user=current_user, campaign=campaign, sponsor=sponsor)

@app.route("/admin/dashboard/all_ad_requests")
@login_required
@admin_required
def all_ad_requests():
    ad_requests=Ad_Request.query.all()
    ad_dict = {}
    for ad_request in ad_requests:
        campaign = Campaign.query.get(ad_request.campaign_id)
        sponsor = User.query.get(campaign.sponsor_id)
        influencer = User.query.get(ad_request.influencer_id)
        ad_dict[ad_request.id] = [ad_request, campaign, sponsor, influencer]
    return render_template("admin/all_ad_requests.html", user=current_user, ad_requests=ad_dict)

@app.route("/admin/dashboard/view/ad_request/<int:adrequest_id>")
@login_required
@admin_required
def admin_view_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    campaign = Campaign.query.get(ad_request.campaign_id)
    sponsor = User.query.get(campaign.sponsor_id)
    influencer = User.query.get(ad_request.influencer_id)
    return render_template("/admin/view_adrequest.html", user=current_user, ad_request=ad_request, campaign=campaign, sponsor=sponsor, influencer=influencer)

@app.route("/admin/dashboard/flag/campaign/<int:campaign_id>")
@login_required
@admin_required
def admin_flag_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    campaign.flagged = True
    db.session.commit()
    flash(f"{campaign.name} flagged successfully.", category="success")
    return redirect(request.referrer)

@app.route("/admin/dashboard/unflag/campaign/<int:campaign_id>")
@login_required
@admin_required
def admin_unflag_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    campaign.flagged = False
    db.session.commit()
    flash(f"{campaign.name} unflagged successfully.", category="success")
    return redirect(request.referrer)

@app.route("/admin/profile")
@login_required
@admin_required
def admin_profile():
    return render_template("admin/admin_profile.html", user=current_user)

@app.route("/admin/profile/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_admin_profile():
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        if not name:
            flash("Name is required.", category="danger")
            return render_template("admin/edit_admin_profile.html", user=current_user)
        if not username:
            flash("Username is required.", category="danger")
            return render_template("admin/edit_admin_profile.html", user=current_user)
        if username != current_user.username:
            user = User.query.filter_by(username=username).first()
            if user:
                flash("Username already exists.", category="danger")
                return render_template("admin/edit_admin_profile.html", user=current_user)
        user = User.query.get(current_user.id)
        user.name = name
        user.username = username
        db.session.commit()
        flash("Profile updated successfully.", category="success")
        return redirect(url_for("admin_profile"))
    return render_template("admin/edit_admin_profile.html", user=current_user)

@app.route("/admin/dashboard/statistics")
@login_required
@admin_required
def admin_statistics():
    influencers = User.query.filter_by(user_type="influencer").all()
    sponsors = User.query.filter_by(user_type="sponsor").all()

    unflagged_influencers = User.query.filter_by(user_type="influencer", flagged=False).all()
    flagged_influencers = User.query.filter_by(user_type="influencer", flagged=True).all()

    unflagged_sponsors = User.query.filter_by(user_type="sponsor", flagged=False).all()
    flagged_sponsors = User.query.filter_by(user_type="sponsor", flagged=True).all()

    influencers = len(influencers) or 0
    sponsors = len(sponsors) or 0

    unflagged_influencers = len(unflagged_influencers) or 0
    flagged_influencers = len(flagged_influencers) or 0

    unflagged_sponsors = len(unflagged_sponsors) or 0
    flagged_sponsors = len(flagged_sponsors) or 0

    labels = ["influencers", "sponsors"]
    data = [influencers, sponsors]

    influencer_labels = ["unflagged", "flagged"]
    influencer_data = [unflagged_influencers, flagged_influencers]

    sponsor_labels = ["unflagged", "flagged"]
    sponsor_data = [unflagged_sponsors, flagged_sponsors]

    if sum(data) > 0:
        plt.pie(data, labels=labels, autopct='%1.1f%%')
        plt.legend(title="Users")
        plt.savefig("static/admin_stats/users_pie.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available or data not suitable to draw pie chart.', ha='center', va='center')
        plt.axis("off")
        plt.savefig("static/admin_stats/users_pie.png", bbox_inches='tight')

    plt.clf()

    if sum(data) > 0:
        plt.bar(labels, data)
        for i, v in enumerate(data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("User Type")
        plt.ylabel("Count")
        plt.title("Users")
        plt.savefig("static/admin_stats/users_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/admin_stats/users_bar.png", bbox_inches='tight')

    plt.clf()

    if sum(influencer_data) > 0:
        plt.bar(influencer_labels, influencer_data)
        for i, v in enumerate(influencer_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Influencers")
        plt.savefig("static/admin_stats/influencers_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/admin_stats/influencers_status_bar.png", bbox_inches='tight')

    plt.clf()

    if sum(sponsor_data) > 0:
        plt.bar(sponsor_labels, sponsor_data)
        for i, v in enumerate(sponsor_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Sponsors")
        plt.savefig("static/admin_stats/sponsors_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/admin_stats/sponsors_status_bar.png", bbox_inches='tight')

    plt.clf()

    unflagged_campaigns = Campaign.query.filter_by(flagged=0).all()
    flagged_campaigns = Campaign.query.filter_by(flagged=1).all()

    unflagged_campaigns = len(unflagged_campaigns) or 0
    flagged_campaigns = len(flagged_campaigns) or 0

    campaign_labels = ["unflagged", "flagged"]
    campaign_data = [unflagged_campaigns, flagged_campaigns]

    if sum(campaign_data) > 0:
        plt.bar(campaign_labels, campaign_data)
        for i, v in enumerate(campaign_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Campaigns")
        plt.savefig("static/admin_stats/campaigns_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/admin_stats/campaigns_status_bar.png", bbox_inches='tight')

    plt.clf()

    pending_adrequests = Ad_Request.query.filter_by(status="pending").all()
    accepted_adrequests = Ad_Request.query.filter_by(status="accepted").all()
    rejected_adrequests = Ad_Request.query.filter_by(status="rejected").all()

    pending_adrequests = len(pending_adrequests) or 0
    accepted_adrequests = len(accepted_adrequests) or 0
    rejected_adrequests = len(rejected_adrequests) or 0

    adrequests_labels = ["Pending", "Accepted", "Rejected"]
    adrequests_data = [pending_adrequests, accepted_adrequests, rejected_adrequests]

    if sum(adrequests_data) > 0:
        plt.bar(adrequests_labels, adrequests_data)
        for i, v in enumerate(adrequests_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Ad Requests")
        plt.savefig("static/admin_stats/adrequests_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/admin_stats/adrequests_status_bar.png", bbox_inches='tight')

    plt.close()
    return render_template("/admin/statistics.html", user=current_user)

@app.route("/influencer/dashboard")
@login_required
@influencer_required
def influencer_dashboard():
    active_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="accepted", completed=False).all()
    completed_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="accepted", completed=True).all()
    active_campaigns = []
    completed_campaigns = []
    for ad in active_ads:
        campaign = Campaign.query.get(ad.campaign_id)
        active_campaigns.append(campaign)
    for ad in completed_ads:
        campaign = Campaign.query.get(ad.campaign_id)
        completed_campaigns.append(campaign)
    return render_template("influencer/influencer_dashboard.html", user=current_user, active_campaigns=active_campaigns, completed_campaigns=completed_campaigns)

@app.route("/influencer/dashboard/ad_requests")
@login_required
@influencer_required
def influencer_dashboard_adrequests():
    ad_requests = Ad_Request.query.filter_by(influencer_id=current_user.id, requested_by="sponsor", status="pending").all()
    active_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="accepted", completed=False).all()
    completed_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="accepted", completed=True).all()
    sent_adrequests = Ad_Request.query.filter_by(influencer_id=current_user.id, requested_by="influencer", status="pending").all()
    ads = {}
    active_dict = {}
    completed_dict = {}
    sent_adrequests_dict = {}
    for ad_request in ad_requests:
        campaign = Campaign.query.get(ad_request.campaign_id)
        campaign_name = campaign.name
        sponsor = User.query.get(campaign.sponsor_id)
        sponsor_name = sponsor.name
        ads[ad_request.id] = [ad_request, campaign_name, sponsor_name]
    for ad_request in active_ads:
        campaign = Campaign.query.get(ad_request.campaign_id)
        campaign_name = campaign.name
        sponsor = User.query.get(campaign.sponsor_id)
        sponsor_name = sponsor.name
        active_dict[ad_request.id] = [ad_request, campaign_name, sponsor_name]
    for ad_request in completed_ads:
        campaign = Campaign.query.get(ad_request.campaign_id)
        campaign_name = campaign.name
        sponsor = User.query.get(campaign.sponsor_id)
        sponsor_name = sponsor.name
        completed_dict[ad_request.id] = [ad_request, campaign_name, sponsor_name]
    for ad_request in sent_adrequests:
        campaign = Campaign.query.get(ad_request.campaign_id)
        campaign_name = campaign.name
        sponsor = User.query.get(campaign.sponsor_id)
        sponsor_name = sponsor.name
        sent_adrequests_dict[ad_request.id] = [ad_request, campaign_name, sponsor_name]
    return render_template("influencer/ad_requests.html", user=current_user, ad_requests=ads, active_ads=active_dict, completed_ads=completed_dict, sent_ads=sent_adrequests_dict)

@app.route("/influencer/dashboard/view/ad_request/<int:adrequest_id>")
@login_required
@influencer_required
def influencer_dashboard_view_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    campaign = Campaign.query.get(ad_request.campaign_id)
    campaign_name = campaign.name
    sponsor = User.query.get(campaign.sponsor_id)
    sponsor_name = sponsor.name
    return render_template("influencer/view_adrequest.html", user=current_user, ad_request=ad_request, campaign_name=campaign_name, sponsor_name=sponsor_name)

@app.route("/influencer/dashboard/accept/ad_request/<int:adrequest_id>")
@login_required
@influencer_required
def influencer_dashboard_accept_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    ad_request.status = "accepted"
    db.session.commit()
    flash("Ad request accepted successfully.", category="success")
    return redirect(url_for("influencer_dashboard"))

@app.route("/influencer/dashboard/reject/ad_request/<int:adrequest_id>")
@login_required
@influencer_required
def influencer_dashboard_reject_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    ad_request.status = "rejected"
    db.session.commit()
    flash("Ad request rejected successfully.", category="success")
    return redirect(url_for("influencer_dashboard"))

@app.route("/influencer/dashboard/view/campaign/<int:campaign_id>")
@login_required
@influencer_required
def influencer_dashboard_view_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    sponsor = User.query.get(campaign.sponsor_id)
    active_ads = Ad_Request.query.filter_by(campaign_id=campaign_id, influencer_id=current_user.id, requested_by="sponsor", status="accepted", completed=False).all()
    completed_ads = Ad_Request.query.filter_by(campaign_id=campaign_id, influencer_id=current_user.id, requested_by="sponsor", status="accepted", completed=True).all()
    return render_template("influencer/view_campaign.html", user=current_user, campaign=campaign, sponsor=sponsor, active_ads=active_ads, completed_ads=completed_ads)

@app.route("/influencer/dashboard/completed/ad/<int:adrequest_id>")
@login_required
@influencer_required
def influencer_dashboard_completed_ad(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    ad_request.completed = True
    db.session.commit()
    flash("Ad completed successfully.", category="success")
    return redirect(request.referrer)

@app.route("/influencer/dashboard/find/campaigns", methods=["GET", "POST"])
@login_required
@influencer_required
def influencer_dashboard_find_campaigns():
    if request.method == "POST":
        search_type = request.form["search_type"]
        search_string = request.form["search"]
        if search_type == "":
            flash("Please select search type.", category="danger")
            return redirect(request.referrer)
        if search_type == "cname":
            query = Campaign.query.filter(Campaign.name.ilike(f'%{search_string}%'))
            if query:
                results = query.filter(Campaign.flagged == 0, Campaign.visibility=="public").all()
                return render_template("influencer/find_campaigns.html", user=current_user, campaigns=results)
            flash("No search results.", category="danger")
            return render_template("influencer/find_campaigns.html", user=current_user, campaigns=[])
        if search_type == "description":
            query = Campaign.query.filter(Campaign.description.ilike(f'%{search_string}%'))
            if query:
                results = query.filter(Campaign.flagged == 0, Campaign.visibility=="public").all()
                return render_template("influencer/find_campaigns.html", user=current_user, campaigns=results)
            flash("No search results.", category="danger")
            return render_template("influencer/find_campaigns.html", user=current_user, campaigns=[])
        if search_type == "goals":
            query = Campaign.query.filter(Campaign.goals.ilike(f'%{search_string}%'))
            if query:
                results = query.filter(Campaign.flagged == 0, Campaign.visibility=="public").all()
                return render_template("influencer/find_campaigns.html", user=current_user, campaigns=results)
            flash("No search results.", category="danger")
            return render_template("influencer/find_campaigns.html", user=current_user, campaigns=[])
        if search_type == "maxbudget":
            try:
                maxbudget = int(search_string)
            except Exception as e:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            if maxbudget < 0:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            query = Campaign.query.filter(Campaign.budget <= maxbudget)
            if query:
                results = query.filter(Campaign.flagged==0, Campaign.visibility=="public").all()
                return render_template("influencer/find_campaigns.html", user=current_user, campaigns=results)
            flash("No search results.", category="danger")
            return render_template("influencer/find_campaigns.html", user=current_user, campaigns=[])
        if search_type == "minbudget":
            try:
                minbudget = int(search_string)
            except Exception as e:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            if minbudget < 0:
                flash("Invalid budget.", category="danger")
                return redirect(request.referrer)
            query = Campaign.query.filter(Campaign.budget >= minbudget)
            if query:
                results = query.filter(Campaign.flagged==0, Campaign.visibility=="public").all()
                return render_template("influencer/find_campaigns.html", user=current_user, campaigns=results)
            flash("No search results.", category="danger")
            return render_template("influencer/find_campaigns.html", user=current_user, campaigns=[])
    campaigns = Campaign.query.filter_by(flagged=False, visibility="public").all()
    return render_template("influencer/find_campaigns.html", user=current_user, campaigns=campaigns)

@app.route("/influencer/send/ad_request/<int:campaign_id>", methods=["GET", "POST"])
@login_required
@influencer_required
def influencer_send_adrequest(campaign_id):
    if request.method == "POST":
        messages = request.form["message"]
        requirements = request.form["requirement"]
        payment_amount = request.form["amount"]
        if not messages:
            flash("Messages is required.", category="danger")
            return render_template("influencer/send_adrequest.html", user=current_user, campaign=Campaign.query.get(campaign_id))
        if not requirements:
            flash("Requirements is required.", category="danger")
            return render_template("influencer/send_adrequest.html", user=current_user, campaign=Campaign.query.get(campaign_id))
        if not payment_amount:
            flash("Payment amount is required.", category="danger")
            return render_template("influencer/send_adrequest.html", user=current_user, campaign=Campaign.query.get(campaign_id))
        ad_request = Ad_Request(campaign_id=campaign_id, influencer_id=current_user.id, messages=messages, requirements=requirements, payment_amount=payment_amount, requested_by="influencer")
        db.session.add(ad_request)
        db.session.commit()
        flash("Ad request sent successfully.", category="success")
        return redirect(url_for("influencer_dashboard_adrequests"))
    return render_template("influencer/send_adrequest.html", user=current_user, campaign=Campaign.query.get(campaign_id))

@app.route("/influencer/profile")
@login_required
@influencer_required
def influencer_profile():
    user = User.query.get(current_user.id)
    platforms = json.loads(user.platforms)
    return render_template("influencer/influencer_profile.html", user=user, platforms=platforms)

@app.route("/influencer/profile/edit", methods=["GET", "POST"])
@login_required
@influencer_required
def edit_influencer_profile():
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        platforms = request.form.getlist('platforms')
        category = request.form["category"]
        niche = request.form["niche"]
        follower_count = request.form["subscribers"]
        if not name:
            flash("Name is required.", category="danger")
            return render_template("influencer/edit_influencer_profile.html", user=current_user)
        if not username:
            flash("Username is required.", category="danger")
            return render_template("influencer/edit_influencer_profile.html", user=current_user)
        if platforms == []:
            flash("Atleast one platform should be selected", category="danger")
            return render_template("influencer/edit_influencer_profile.html", user=current_user)
        if not category:
            flash("Category is required.", category="danger")
            return render_template("influencer/edit_influencer_profile.html", user=current_user)
        if not niche:
            flash("Niche is required.", category="danger")
            return render_template("influencer/edit_influencer_profile.html", user=current_user)
        if not follower_count:
            flash("Subscribers/Followers is required.", category="danger")
            return render_template("influencer/edit_influencer_profile.html", user=current_user)
        if username != current_user.username:
            user = User.query.filter_by(username=username).first()
            if user:
                flash("Username already exists.", category="danger")
                return render_template("influencer/edit_influencer_profile.html", user=current_user)
        user = User.query.get(current_user.id)
        user.name = name
        user.username = username
        user.category = category
        user.niche = niche
        user.follower_count = follower_count
        user.platforms = json.dumps(platforms)
        db.session.commit()
        flash("Profile updated successfully.", category="success")
        return redirect(url_for("influencer_profile"))
    platforms = json.loads(current_user.platforms)
    return render_template("influencer/edit_influencer_profile.html", user=current_user, platforms=platforms)

@app.route("/influencer/dashboard/statistics")
@login_required
@influencer_required
def influencer_statistics():
    pending_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="pending", requested_by="sponsor").all()
    rejected_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="rejected", requested_by="sponsor").all()
    active_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="accepted", completed=False).all()
    completed_ads = Ad_Request.query.filter_by(influencer_id=current_user.id, status="accepted", completed=True).all()
    active_campaigns = []
    completed_campaigns = []
    rejected_campaigns = []
    for ad in active_ads:
        campaign = Campaign.query.get(ad.campaign_id)
        active_campaigns.append(campaign)
    for ad in completed_ads:
        campaign = Campaign.query.get(ad.campaign_id)
        completed_campaigns.append(campaign)
    for ad in rejected_ads:
        campaign = Campaign.query.get(ad.campaign_id)
        rejected_campaigns.append(campaign)
    active_campaigns = len(active_campaigns)
    completed_campaigns = len(completed_campaigns)
    rejected_campaigns = len(rejected_campaigns)

    campaigns_labels = ["Active", "Completed", "Rejected"]
    campaigns_data = [active_campaigns, completed_campaigns, rejected_campaigns]

    if sum(campaigns_data) > 0:
        plt.bar(campaigns_labels, campaigns_data)
        for i, v in enumerate(campaigns_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Campaigns")
        plt.savefig("static/influencer_stats/campaigns_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/influencer_stats/campaigns_status_bar.png", bbox_inches='tight')

    plt.clf()

    if sum(campaigns_data) > 0:
        plt.pie(campaigns_data, labels=campaigns_labels, autopct='%1.1f%%')
        plt.legend(title="Campaigns")
        plt.savefig("static/influencer_stats/campaigns_status_pie.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available or data not suitable to draw pie chart.', ha='center', va='center')
        plt.axis("off")
        plt.savefig("static/influencer_stats/campaigns_status_pie.png", bbox_inches='tight')

    plt.clf()

    pending_ads = len(pending_ads) or 0
    active_ads = len(active_ads) or 0
    completed_ads = len(completed_ads) or 0
    rejected_ads = len(rejected_ads) or 0

    ads_labels = ["New", "Active", "Completed", "Rejected"]
    ads_data = [pending_ads, active_ads, completed_ads, rejected_ads]

    if sum(ads_data) > 0:
        plt.bar(ads_labels, ads_data)
        for i, v in enumerate(ads_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Ad requests")
        plt.savefig("static/influencer_stats/adrequests_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/influencer_stats/adrequests_status_bar.png", bbox_inches='tight')

    plt.close()
    return render_template("influencer/statistics.html", user=current_user)

@app.route("/sponsor/dashboard")
@login_required
@sponsor_required
def sponsor_dashboard():
    active_campaigns=Campaign.query.filter_by(sponsor_id=current_user.id, flagged=False).all()
    flagged_campaigns=Campaign.query.filter_by(sponsor_id=current_user.id, flagged=True).all()
    active_dict = {}
    flagged_dict = {}
    import math
    for campaign in active_campaigns:
        all_ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id).all()
        completed_ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id, completed=True).all()
        all_ad_requests = len(all_ad_requests) or 0
        completed_ad_requests = len(completed_ad_requests) or 0
        progress = 0
        if all_ad_requests != 0:
            progress = math.ceil((completed_ad_requests/all_ad_requests) * 100)
        active_dict[campaign.id] = [campaign, progress]
    for campaign in flagged_campaigns:
        all_ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id).all()
        completed_ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id, completed=True).all()
        all_ad_requests = len(all_ad_requests) or 0
        completed_ad_requests = len(completed_ad_requests) or 0
        progress = math.ceil((completed_ad_requests/all_ad_requests) * 100)
        flagged_dict[campaign.id] = [campaign, progress]
    return render_template("sponsor/sponsor_dashboard.html", user=current_user, active_campaigns=active_dict, flagged_campaigns=flagged_dict)

@app.route("/sponsor/dashboard/influencers", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_dashboard_influencers():
    if request.method == "POST":
        search_type = request.form["search_type"]
        search_string = request.form["search"]
        if search_type == "":
            flash("Please select search type.", category="danger")
            return redirect(url_for("sponsor_dashboard_influencers"))
        if search_type == "iname":
            query = User.query.filter(User.name.ilike(f'%{search_string}%'))
            if query:
                query = query.filter_by(user_type="influencer")
            results = query.filter(User.flagged == 0).all()
            return render_template("sponsor/find_influencers.html", user=current_user, influencers=results)
        if search_type == "maxfollowers":
            try:
                maxfollowers = int(search_string)
            except Exception as e:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("sponsor_dashboard_influencers"))
            if maxfollowers < 0:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("sponsor_dashboard_influencers"))
            query = User.query.filter(User.follower_count <= maxfollowers)
            if query:
                query.filter_by(user_type="influencer")
            results = query.filter(User.flagged == 0).all()
            return render_template("sponsor/find_influencers.html", user=current_user, influencers=results)
        if search_type == "minfollowers":
            try:
                minfollowers = int(search_string)
            except Exception as e:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("sponsor_dashboard_influencers"))
            if minfollowers < 0:
                flash("Invalid followers.", category="danger")
                return redirect(url_for("sponsor_dashboard_influencers"))
            query = User.query.filter(User.follower_count >= minfollowers)
            if query:
                query.filter_by(user_type="influencer")
            results = query.filter(User.flagged == 0).all()
            return render_template("sponsor/find_influencers.html", user=current_user, influencers=results)
        if search_type == "category":
            query = User.query.filter(User.category.ilike(f'%{search_string}%'))
            if query:
                query = query.filter_by(user_type="influencer")
            results = query.filter(User.flagged == 0).all()
            return render_template("sponsor/find_influencers.html", user=current_user, influencers=results)
        if search_type == "niche":
            query = User.query.filter(User.niche.ilike(f'%{search_string}%'))
            if query:
                query = query.filter_by(user_type="influencer")
            results = query.filter(User.flagged == 0).all()
            return render_template("sponsor/find_influencers.html", user=current_user, influencers=results)
    return render_template("sponsor/find_influencers.html", user=current_user, influencers=User.query.filter_by(user_type="influencer", flagged=False).all())

@app.route("/sponsor/dashboard/create/campaign", methods=["GET", "POST"])
@login_required
@sponsor_required
def create_campaign():
    if request.method == "POST":
        sponsor_id = current_user.id
        name = request.form["name"]
        description = request.form["description"]
        start_date = request.form["start_date"]
        end_date = request.form["end_date"]
        budget = request.form["budget"]
        goals = request.form["goals"]
        visibility = request.form["visibility"]
        if not name:
            flash("Name is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        if not description:
            flash("Description is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        if not start_date:
            flash("Start date is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        if not end_date:
            flash("End date is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)

        if not budget:
            flash("Budget is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        if not goals:
            flash("Goals is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        if not visibility:
            flash("Visibility is required.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except Exception as e:
            flash("Invalid start or end date.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        if start_date > end_date:
            flash("Start date should be before end date.", category="danger")
            return render_template("sponsor/create_campaign.html", user=current_user)
        try:
            budget = int(budget)
        except Exception as e:
            flash("Invalid budget.", category="danger")
            render_template("sponsor/create_campaign.html", user=current_user)
        campaign = Campaign(sponsor_id=sponsor_id, name=name, description=description, start_date=start_date, end_date=end_date, budget=budget, goals=goals, visibility=visibility)
        db.session.add(campaign)
        db.session.commit()
        flash("Campaign created successfully.", category="success")
        return redirect(url_for("sponsor_dashboard"))
    return render_template("sponsor/create_campaign.html", user=current_user)

@app.route("/sponsor/dashboard/view/campaign/<int:campaign_id>")
@login_required
@sponsor_required
def sponsor_view_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    new_adrequests = {}
    sent_adrequests = {}
    received_adrequests = {}
    ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id).all()
    campaign_name = campaign.name
    for ad_request in ad_requests:
        influencer = User.query.get(ad_request.influencer_id)
        influencer_name = influencer.name
        if ad_request.requested_by == "influencer":
            if ad_request.status == "pending":
                new_adrequests[ad_request.id] = [ad_request, campaign_name, influencer_name]
            else:
                received_adrequests[ad_request.id] = [ad_request, campaign_name, influencer_name]
        else:
            sent_adrequests[ad_request.id] = [ad_request, campaign_name, influencer_name]
    return render_template("sponsor/view_campaign.html", user=current_user, campaign=campaign, new_adrequests=new_adrequests, sent_adrequests=sent_adrequests, received_adrequests=received_adrequests)

@app.route("/sponsor/dashboard/edit/campaign/<int:campaign_id>", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_edit_campaign(campaign_id):
    if request.method == "POST":
        name = request.form["name"]
        description = request.form["description"]
        start_date = request.form["start_date"]
        end_date = request.form["end_date"]
        budget = request.form["budget"]
        goals = request.form["goals"]
        visibility = request.form["visibility"]
        if not name:
            flash("Name is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign=Campaign.query.get(campaign_id))
        if not description:
            flash("Description is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        if not start_date:
            flash("Start date is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        if not end_date:
            flash("End date is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))

        if not budget:
            flash("Budget is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        if not goals:
            flash("Goals is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        if not visibility:
            flash("Visibility is required.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except Exception as e:
            flash("Invalid start or end date.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        if start_date > end_date:
            flash("Start date should be before end date.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        try:
            budget = int(budget)
        except Exception as e:
            flash("Invalid budget.", category="danger")
            return render_template("sponsor/edit_campaign.html", user=current_user, campaign = Campaign.query.get(campaign_id))
        campaign = Campaign.query.get(campaign_id)
        campaign.name = name
        campaign.description = description
        campaign.start_date = start_date
        campaign.end_date = end_date
        campaign.budget = budget
        campaign.goals = goals
        campaign.visibility = visibility
        db.session.commit()
        flash("Campaign updated successfully.", category="success")
        return redirect(url_for("view_campaign", campaign_id=campaign.id))
    campaign = Campaign.query.get(campaign_id)
    if campaign.flagged:
        flash("You can't edit flagged campaign.", category="danger")
        return render_template("sponsor/view_campaign.html", user=current_user, campaign=campaign)
    return render_template("sponsor/edit_campaign.html", user=current_user, campaign=campaign)

@app.route("/sponsor/dashboard/delete/campaign/<int:campaign_id>", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_delete_campaign(campaign_id):
    if request.method == "POST":
        checked = request.form.getlist("delete_check")
        if checked == []:
            flash("Please check the checkbox to delete campaign.", category="danger")
            return redirect(url_for("delete_campaign", user=current_user, campaign_id=campaign_id))
        campaign = Campaign.query.get(campaign_id)
        if campaign:
            db.session.delete(campaign)
            db.session.commit()
            flash("Campaign deleted successfully.", category="success")
            return redirect(url_for("sponsor_dashboard", user=current_user))
        flash("Campaign not found.", category="danger")
        return redirect(url_for("sponsor_dashboard", user=current_user))
    return render_template("sponsor/delete_campaign.html", user=current_user, campaign=Campaign.query.get(campaign_id))

@app.route("/sponsor/dashboard/send/ad_request/<int:influencer_id>", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_send_adrequest(influencer_id):
    if request.method == "POST":
        influencer_id = request.form["influencer_id"]
        campaign_id = request.form["campaign_id"]
        requiements = request.form["requirement"]
        messages = request.form["message"]
        payment_amount = request.form["amount"]
        if not influencer_id:
            flash("Influencer is required.", category="danger")
            return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())
        if not campaign_id:
            flash("Campaign is required.", category="danger")
            return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())
        if not requiements:
            flash("Requirements is required.", category="danger")
            return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())
        if not messages:
            flash("Message is required.", category="danger")
            return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())
        if not payment_amount:
            flash("Payment amount is required.", category="danger")
            return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())
        try:
            payment_amount = int(payment_amount)
        except Exception as e:
            flash("Invalid payment amount.", category="danger")
            return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())
        campaign = Campaign.query.get(campaign_id)
        if campaign.flagged:
            flash("You can't send ad request for flagged campaign.", category="danger")
            return redirect(url_for("sponsor_send_adrequest"))
        ad_request = Ad_Request(campaign_id=campaign_id, influencer_id=influencer_id, requirements=requiements, messages=messages, payment_amount=payment_amount, requested_by="sponsor")
        db.session.add(ad_request)
        db.session.commit()
        flash("Ad request sent successfully.", category="success")
        return redirect(url_for("sponsor_payment", amount=ad_request.payment_amount))
    return render_template("sponsor/send_adrequest.html", user=current_user, influencer=User.query.get(influencer_id), campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())

@app.route("/sponsor/dashboard/view/ad_request/<int:adrequest_id>")
@login_required
@sponsor_required
def sponsor_view_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    campaign = Campaign.query.get(ad_request.campaign_id)
    influencer = User.query.get(ad_request.influencer_id)
    platforms = json.loads(influencer.platforms)
    return render_template("sponsor/view_adrequest.html", user=current_user, ad_request=ad_request, campaign=campaign, influencer=influencer, platforms=platforms)

@app.route("/sponsor/dashboard/accept/ad_request/<int:adrequest_id>")
@login_required
@sponsor_required
def sponsor_accept_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    ad_request.status = "accepted"
    db.session.commit()
    flash("Ad request accepted successfully.", category="success")
    return redirect(url_for("sponsor_payment", amount=ad_request.payemnt_amount))

@app.route("/sponsor/dashboard/reject/ad_request/<int:adrequest_id>")
@login_required
@sponsor_required
def sponsor_reject_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    ad_request.status = "rejected"
    db.session.commit()
    flash("Ad request rejected successfully.", category="success")
    return redirect(request.referrer)

@app.route("/sponsor/dashboard/ad_requests", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_dashboard_adrequests():
    campaigns = Campaign.query.filter_by(sponsor_id=current_user.id).all()
    new_adrequests = {}
    sent_adrequests = {}
    received_adrequests = {}
    for campaign in campaigns:
        ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id).all()
        campaign_name = campaign.name
        for ad_request in ad_requests:
            influencer = User.query.get(ad_request.influencer_id)
            influencer_name = influencer.name
            if ad_request.requested_by == "influencer":
                if ad_request.status == "pending":
                    new_adrequests[ad_request.id] = [ad_request, campaign_name, influencer_name]
                else:
                    received_adrequests[ad_request.id] = [ad_request, campaign_name, influencer_name]
            else:
                sent_adrequests[ad_request.id] = [ad_request, campaign_name, influencer_name]
    return render_template("sponsor/ad_requests.html", user=current_user, new_adrequests=new_adrequests, sent_adrequests=sent_adrequests, received_adrequests=received_adrequests)

@app.route("/sponsor/dashboard/edit/ad_request/<int:adrequest_id>", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_edit_adrequest(adrequest_id):
    if request.method == "POST":
        influencer_id = request.form["influencer_id"]
        campaign_id = request.form["campaign_id"]
        requiements = request.form["requirement"]
        messages = request.form["message"]
        payment_amount = request.form["amount"]
        if not influencer_id:
            flash("Influencer is required.", category="danger")
            return redirect(request.referrer)
        if not campaign_id:
            flash("Campaign is required.", category="danger")
            return redirect(request.referrer)
        if not requiements:
            flash("Requirements is required.", category="danger")
            return redirect(request.referrer)
        if not messages:
            flash("Message is required.", category="danger")
            return redirect(request.referrer)
        if not payment_amount:
            flash("Payment amount is required.", category="danger")
            return redirect(request.referrer)
        try:
            payment_amount = int(payment_amount)
        except Exception as e:
            flash("Invalid payment amount.", category="danger")
            return redirect(request.referrer)
        ad_request = Ad_Request.query.get(adrequest_id)
        ad_request.campaign_id = campaign_id
        ad_request.requirements = requiements
        ad_request.messages = messages
        ad_request.payment_amount = payment_amount
        db.session.commit()
        flash("Ad request edited successfully.", category="success")
        return redirect(url_for("sponsor_dashboard_adrequests"))
    ad_request = Ad_Request.query.get(adrequest_id)
    campaign = Campaign.query.get(ad_request.campaign_id)
    sponsor = User.query.get(campaign.sponsor_id)
    influencer = User.query.get(ad_request.influencer_id)
    return render_template("/sponsor/edit_adrequest.html", user=current_user, ad_request=ad_request, sponsor=sponsor, influencer=influencer, campaigns=Campaign.query.filter_by(sponsor_id=current_user.id).all())

@app.route("/sponsor/dashboard/delete/ad_request/<int:adrequest_id>", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_delete_adrequest(adrequest_id):
    ad_request = Ad_Request.query.get(adrequest_id)
    db.session.delete(ad_request)
    db.session.commit()
    flash("Ad Request deleted successfully.", category="success")
    return redirect(request.referrer)

@app.route("/sponsor/profile")
@login_required
@sponsor_required
def sponsor_profile():
    return render_template("sponsor/sponsor_profile.html", user=current_user)

@app.route("/sponsor/profile/edit", methods=["GET", "POST"])
@login_required
@sponsor_required
def edit_sponsor_profile():
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        industry = request.form["industry"]
        budget = request.form["budget"]
        if not name:
            flash("Name is required.", category="danger")
            return render_template("sponsor/edit_sponsor_profile.html", user=current_user)
        if not username:
            flash("Username is required.", category="danger")
            return render_template("sponsor/edit_sponsor_profile.html", user=current_user)
        if not industry:
            flash("Industry is required.", category="danger")
            return render_template("sponsor/edit_sponsor_profile.html", user=current_user)
        if not budget:
            flash("Budget is required.", category="danger")
            return render_template("sponsor/edit_sponsor_profile.html", user=current_user)
        if username != current_user.username:
            user = User.query.filter_by(username=username).first()
            if user:
                flash("Username already exists.", category="danger")
                return render_template("sponsor/edit_sponsor_profile.html", user=current_user)
        user = User.query.get(current_user.id)
        user.name = name
        user.username = username
        user.industry = industry
        user.budget = budget
        db.session.commit()
        flash("Profile updated successfully.", category="success")
        return redirect(url_for("sponsor_profile"))
    return render_template("sponsor/edit_sponsor_profile.html", user=current_user)

@app.route("/sponsor/payment/<int:amount>", methods=["GET", "POST"])
@login_required
@sponsor_required
def sponsor_payment(amount):
    if request.method == "POST":
        card_number = request.form["cardNumber"]
        expiry = request.form["cardExpiry"]
        cvv = request.form["cardCvv"]
        cardholder_name = request.form["cardHolderName"]
        if not card_number:
            flash("Card number is required.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        if not expiry:
            flash("Expiry is required.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        if not cvv:
            flash("CVV is required.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        if not cardholder_name:
            flash("Cardholder name is required.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        import re
        if not re.match(r'^[0-9]{16}$', card_number):
            flash("Invalid card number.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        if not re.match(r'^[0-9]{2}/[0-9]{2}$', expiry):
            flash("Invalid expiry month or year.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        if not re.match(r'^[0-9]{3}$', cvv):
            flash("Invalid CVV.", category="danger")
            return render_template("sponsor/payment.html", user=current_user)
        flash("Payment successful.", category="success")
        return redirect(url_for("sponsor_dashboard_adrequests"))
    return render_template("sponsor/payment.html", user=current_user, amount=amount)

@app.route("/sponsor/dashboard/statistics")
@login_required
@sponsor_required
def sponsor_statistics():
    active_campaigns=Campaign.query.filter_by(sponsor_id=current_user.id, flagged=False).all()
    flagged_campaigns=Campaign.query.filter_by(sponsor_id=current_user.id, flagged=True).all()
    active_campaigns = len(active_campaigns) or 0
    flagged_campaigns = len(flagged_campaigns) or 0

    campaigns_labels = ["active", "flagged"]
    campaigns_data = [active_campaigns, flagged_campaigns]

    if sum(campaigns_data) > 0:
        plt.bar(campaigns_labels, campaigns_data)
        for i, v in enumerate(campaigns_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Campaigns")
        plt.savefig("static/sponsor_stats/campaigns_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/sponsor_stats/campaigns_status_bar.png", bbox_inches='tight')

    plt.clf()

    if sum(campaigns_data) > 0:
        plt.pie(campaigns_data, labels=campaigns_labels, autopct='%1.1f%%')
        plt.legend(title="Campaigns")
        plt.savefig("static/sponsor_stats/campaigns_status_pie.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available or data not suitable to show pie chart.', ha='center', va='center')
        plt.axis("off")
        plt.savefig("static/sponsor_stats/campaigns_status_pie.png", bbox_inches='tight')

    plt.clf()

    campaigns = Campaign.query.filter_by(sponsor_id=current_user.id).all()
    new_adrequests = []
    sent_adrequests = []
    received_adrequests = []
    for campaign in campaigns:
        ad_requests = Ad_Request.query.filter_by(campaign_id=campaign.id).all()
        for ad_request in ad_requests:
            if ad_request.requested_by == "influencer":
                if ad_request.status == "pending":
                    new_adrequests.append(ad_request)
                else:
                    received_adrequests.append(ad_request)
            else:
                sent_adrequests.append(ad_request)
    new_ads = len(new_adrequests)
    sent_ads = len(sent_adrequests)
    received_ads = len(received_adrequests)

    ads_labels = ["New", "Sent", "Received"]
    ads_data = [new_ads, sent_ads, received_ads]

    if sum(ads_data) > 0:
        plt.bar(ads_labels, ads_data)
        for i, v in enumerate(ads_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Type of Ad")
        plt.ylabel("Count")
        plt.title("Ad Requests")
        plt.savefig("static/sponsor_stats/adrequests_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/sponsor_stats/adrequests_status_bar.png", bbox_inches='tight')

    plt.clf()

    accepted_sent_adrequests = []
    rejected_sent_adrequests = []
    for ad in sent_adrequests:
        if ad.status == "accepted":
            accepted_sent_adrequests.append(ad)
        else:
            rejected_sent_adrequests.append(ad)
    accepted_sent_adrequests = len(accepted_sent_adrequests)
    rejected_sent_adrequests = len(rejected_sent_adrequests)

    sent_adrequests_labels = ["Accepted", "Rejected"]
    sent_adrequests_data = [accepted_sent_adrequests, rejected_sent_adrequests]

    if sum(sent_adrequests_data) > 0:
        plt.bar(sent_adrequests_labels, sent_adrequests_data)
        for i, v in enumerate(sent_adrequests_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Sent Ad Requests")
        plt.savefig("static/sponsor_stats/sent_adrequests_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/sponsor_stats/sent_adrequests_status_bar.png", bbox_inches='tight')

    plt.clf()

    accepted_received_adrequests = []
    rejected_received_adrequests = []
    for ad in received_adrequests:
        if ad.status == "accepted":
            accepted_received_adrequests.append(ad)
        else:
            rejected_received_adrequests.append(ad)
    accepted_received_adrequests = len(accepted_received_adrequests)
    rejected_received_adrequests = len(rejected_received_adrequests)

    received_adrequests_labels = ["Accepted", "Rejected"]
    received_adrequests_data = [accepted_received_adrequests, rejected_received_adrequests]

    if sum(received_adrequests_data) > 0:
        plt.bar(received_adrequests_labels, received_adrequests_data)
        for i, v in enumerate(received_adrequests_data):
            plt.text(i, v + 0.2, str(v))
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.title("Received Ad Requests")
        plt.savefig("static/sponsor_stats/received_adrequests_status_bar.png", bbox_inches='tight')
    else:
        plt.text(0.5, 0.5, 'No data available', ha='center', va='center')
        plt.savefig("static/sponsor_stats/received_adrequests_status_bar.png", bbox_inches='tight')

    plt.close()
    return render_template("sponsor/statistics.html", user=current_user)

@app.route("/flag_sponsor/<int:sponsor_id>")
@login_required
@admin_required
def flag_sponsor(sponsor_id):
    flagged_sponsor = User.query.get(sponsor_id)
    if flagged_sponsor:
        flagged_sponsor.flagged = True
        db.session.commit()
        flash(f"{flagged_sponsor.name} flagged successfully.", category="success")
        return redirect(url_for("admin_dashboard"))
    flash("User not found.", category="danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/unflag_sponsor/<int:sponsor_id>")
@login_required
@admin_required
def unflag_sponsor(sponsor_id):
    unflagged_sponsor = User.query.get(sponsor_id)
    if unflagged_sponsor:
        unflagged_sponsor.flagged = False
        db.session.commit()
        flash(f"{unflagged_sponsor.name} unflagged successfully.", category="success")
        return redirect(url_for("admin_dashboard"))
    flash("User not found.", category="danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/flag_influencer/<int:influencer_id>")
@login_required
@admin_required
def flag_influencer(influencer_id):
    flagged_influencer = User.query.get(influencer_id)
    if flagged_influencer:
        flagged_influencer.flagged = True
        db.session.commit()
        flash(f"{flagged_influencer.name} flagged successfully.", category="success")
        return redirect(url_for("all_influencers"))
    flash("User not found.", category="danger")
    return redirect(url_for("all_influencers"))

@app.route("/unflag_influencer/<int:influencer_id>")
@login_required
@admin_required
def unflag_influencer(influencer_id):
    unflagged_influencer = User.query.get(influencer_id)
    if unflagged_influencer:
        unflagged_influencer.flagged = False
        db.session.commit()
        flash(f"{unflagged_influencer.name} unflagged successfully.", category="success")
        return redirect(url_for("all_influencers"))
    flash("User not found.", category="danger")
    return redirect(url_for("all_influencers"))

@app.route("/change_theme")
@login_required
def change_theme():
    current_user.theme = 'dark' if current_user.theme != 'dark' else 'light'
    db.session.commit()
    return redirect(request.referrer)

