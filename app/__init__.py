# !/usr/bin/python
# -*-coding:utf-8 -*-

#程序的工厂函数 初始化Flask_login
import os

from flask import Flask, config
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy

from flask.ext.login import LoginManager

bootstrap=Bootstrap()
mail=Mail()
moment=Moment()
db=SQLAlchemy()

login_manager=LoginManager()
login_manager.session_protection='strong'
login_manager.login_view='auth.login'

# app.config['SQLALCHEMY_DATABASE_URI']=\
#     'sqlite:///'+os.path.join(basedir,'data.sqlite

basedir=os.path.abspath(os.path.dirname(__file__))
# app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN']=True


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

    login_manager.init_app(app)
    from app.auth import  auth as auth_blueprint
    app.register_blueprint(auth_blueprint,url_prefix='/auth')
    #附加路由和自定义的错误页面
    return app

