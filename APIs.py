from models import db, User
from flask_restful import Api, Resource, reqparse, marshal_with, fields
from app import app
from werkzeug.security import generate_password_hash
import json
from flask import request

api = Api(app)

user_args = reqparse.RequestParser()
user_args.add_argument("name", type=str, required=True)
user_args.add_argument("username", type=str, required=True)
user_args.add_argument("password", type=str, required=True)
user_args.add_argument("user_type", type=str, required=True)
user_args.add_argument("flagged", type=bool, required=True)
user_args.add_argument("theme", type=str, required=True)
user_args.add_argument("category", type=str, required=False)
user_args.add_argument("niche", type=str, required=False)
user_args.add_argument("follower_count", type=int, required=False)
user_args.add_argument("platforms", type=str, required=False)
user_args.add_argument("industry", type=str, required=False)
user_args.add_argument("budget", type=int, required=False)

user_output_fields = {
  "id": fields.Integer,
  "name": fields.String,
  "username": fields.String,
  "user_type": fields.String,
  "flagged": fields.Boolean,
  "theme": fields.String,
  "category": fields.String,
  "niche": fields.String,
  "follower_count": fields.Integer,
  "platforms": fields.String,
  "industry": fields.String,
  "budget": fields.Integer
}

class UserResource(Resource):
  @marshal_with(user_output_fields)
  def get(self, user_id=None):
    user = User.query.get(user_id)
    if user_id:
      user = User.query.get(user_id)
      if user:
        return user, 200
      else:
        return {'message': "User not found"}, 404
    else:
      users = User.query.all()
      return users, 200
    
  @marshal_with(user_output_fields)
  def post(self):
    args = user_args.parse_args()
    try:
      user = User(name=args["name"],
                  username=args["username"],
                  password_hash=generate_password_hash(args["password"]),
                  user_type=args["user_type"],
                  flagged=args["flagged"],
                  theme=args["theme"],
                  category=args["category"],
                  niche=args["niche"],
                  follower_count=args["follower_count"],
                  platforms=args["platforms"],
                  industry=args["industry"],
                  budget=args["budget"])
      db.session.add(user)
      db.session.commit()
      return user, 201
    except Exception as e:
      return {"message": str(e)}, 400
  
  def put(self, user_id):
    user = User.query.get(user_id)
    if user:
      args = user_args.parse_args()
      user.name = args.get("name")
      user.username = args.get("username")
      user.password = args.get("password")
      user.user_type = args.get("user_type")
      user.flagged = args.get("flagged")
      user.theme = args.get("theme")
      user.category = args.get("category")
      user.niche = args.get("niche")
      user.follower_count = args.get("follower_count")
      user.platforms = args.get("platforms")
      user.industry = args.get("industry")
      user.budget = args.get("budget")

      db.session.commit()
      return {"message": "User updated successfully."}, 200
    else:
      return {"message": "User not found."}, 404
    
  def delete(self, user_id):
    user = User.query.get(user_id)
    if user:
      db.session.delete(user)
      db.session.commit()
      return {"message": "User deleted successfully."}, 200
    else:
      return {"message": "User not found."}, 404
    
api.add_resource(UserResource, "/api/users", "/api/users/<int:user_id>")