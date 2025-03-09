from flask import Flask

app = Flask(__name__)

import config

import models

import controllers

import APIs

if __name__ == '__main__':
    app.run(debug=True)