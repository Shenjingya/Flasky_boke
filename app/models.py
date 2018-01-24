# !/usr/bin/python
# -*-coding:utf-8 -*-
#import datetime
from datetime import datetime
from werkzeug.security import  generate_password_hash,check_password_hash
from  flask.ext.login import UserMixin,AnonymousUserMixin
from flask.ext.sqlalchemy import SQLAlchemy
import os
from flask import Flask, current_app, config
from .import login_manager
from flask.ext.login import login_required
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from .import db
import hashlib
from flask import request

app=Flask(__name__)

class Permission:
    FOLLOW=0x01
    COMMENT=0x02
    WRITE_ARTICLES=0x04
    MODERATE_COMMENTS=0x08
    ADMINISTER=0x80
#文章模型
class Post(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    body=db.Column(db.Text)
    timestamp=db.Column(db.DateTime,index=True,default=datetime.utcnow())
    author_id=db.Column(db.Integer,db.ForeignKey('users.id'))

#角色权限模型
class Role(db.Model):
    __table__='roles'
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(64),unique=True)
    default=db.Column(db.Boolean,default=False,index=True)
    permissions=db.Column(db.Integer)
    users=db.relationship('User',backref='role',lazy='dynamic')
    #生成虚拟数据-虚拟博客文章
    @staticmethod
    def gernerate_fake(count=100):
        from random import seed,randint
        import forgery_py

        seed()
        user_count=User.query.count()
        for i in range(count):
            #随机文章生成要为文章随机制定一个用户，为了获得不同的随机账户
            u=User.query.offset(randint(0,user_count-1)).first()
            p=Post(body=forgery_py.lorem_ipsum.sentence(randint(1,3)),
                   timestamp=forgery_py.date.date(True))
            db.session.add(p)
            db.session.commit()
    #将角色添加到数据库
    @staticmethod
    def insert_roles():
        roles={
            'User':(Permission.FOLLOW|Permission.COMMENT|Permission.WRITE_ARTICLES),
            'Moderator':(Permission.FOLLOW|Permission.COMMENT|
                         Permission.WRITE_ARTICLES|Permission.MODERATE_COMMENTS,False),
            'Administrator':(0xff,False)
        }
        for r in roles:
            role=Role.query.filter_by(name=r).first()
            if role is None:
                role=Role(name=r)
            role.permissions=roles[r][0]
            role.default=role[r][1]
            db.session.add(role)
        db.session.commit()

class User(UserMixin,db.Model):

    __tablename_='users'
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(64),unique=True,index=True)
    username=db.Column(db.String(64),unique=True,index=True)
    password_hash=db.Column(db.String(128))
    role_id=db.Column(db.Integer,db.ForeignKey('roles.id'))
    password_hash=db.Column(db.String(128))
    #用户信息字段
    name=db.Column(db.String(64))#真实姓名
    location=db.Column(db.String(64))#所在地
    about_me=db.Column(db.Text())#自我介绍
    member_since=db.Column(db.DateTime(),default=datetime.utcnow)#注册时间
    last_seen=db.Column(db.DateTime(),default=datetime.utcnow)#最后访问时间

    confirmed=db.Column(db.Boolean,default=False)
    #和博客模型有外键的关系
    posts=db.relationship('Post',backref='author',lazy='dynamic')#一对多关系

    #生成虚拟数据-虚拟用户
    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.ext import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u=User(email=forgery_py.internet.email_address(),
                   username=forgery_py.internet.user_name(True),
                   password=forgery_py.lorem_ipsum.word(),
                   confirm=True,
                   name=forgery_py.name.full_name(),
                   location=forgery_py.address.city(),
                   about_me=forgery_py.lorem_ipsum.sentence(),
                   member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except:
                db.session.rollback()


    #刷新用户的最后访问时间
    def ping(self):
        self.last_seen=datetime.utcnow()
        db.session.add(self)
    #构建Gravatar URL的方法 添加到User模型中
    def gravatar(self,size=100,default='identicon',rating='g'):
        if request.is_secure:
            url='http://secure.gravatar.com/avatar'
        else:
            url='http://www.gravatar.com/avatar'
        hash=hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.\
            format(url=url,hash=hash,size=size,default=default,rating=rating)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def password(self,password):
        self.password_hash=generate_password_hash(password)
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    # 生成确认令牌 有效期1小时
    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})  # 字符串
    #检验令牌
    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.load(token)  # 原始数据
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    # 生成重置令牌 有效期1小时
    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})  # 字符串
    @staticmethod
    def reset_password(token,new_password):
        s=Serializer(current_app.config['SECRET_KEY'])
        try:
            data=s.loads(token.encode('utf-8'))
        except:
            return False
        user=User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password=new_password
        db.session.add(user)
        return True
    #生成修改邮箱令牌 有效期1个小时
    def generate_email_change_token(self,new_email,expiration=3600):
        s=Serializer(current_app.config['SECRET_KEY'],expiration)
        return s.dumps({'change_email':self.id,'new_email':new_email}).decode('utf-8')
    #检验更改邮箱令牌
    def change_email(self,token):
        s=Serializer(current_app.config['SECRET_KEY'])
        try:
            data=s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('change_email')!= self.id:
            return False
        new_email=data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email=new_email
        self.avatar_hash=hashlib.md5(self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True
    #构造函数
    def __init__(self,**kwargs):
        super(User,self).__init__(**kwargs)#调用基类的构造函数
        #定义默认的用户角色
        if self.role is None:
            #根据电子邮件的地址决定将其设为管理员还是默认角色
            if self.email==current_app.config['FLASKY_ADMIN']:
                self.role=Role.query.filter_by(permissons=0xff).first()
            if self.role is None:
                self.role=Role.query.filter_by(default=True).first()

        #初始化模型时，计算电子邮件散列值并存入数据库中
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash=hashlib.md5(self.email.encode('utf-8')).hexdigest()
    #检查用户是否有指定权限
    def can(self,permissions):
        return self.role is not None and (self.role.permissions & permissions)==permissions
    def is_adminstrator(self):
        return self.can(Permission.ADMINISTER)

    def __repr__(self):
        return '<User %r>' % self.username

class AnonymousUser(AnonymousUserMixin):
    def can(self,permissions):
        return False
    def is_adminstrator(self):
        return False

login_manager.anonymous_user=AnonymousUser

#加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))#返回用户对象

#为了保护路由只让认证的用户访问 未认证的用户访问 会拦截 并把用户发往登录页面
@app.route('/secret')
@login_required
def secret():
    return 'only authenticated users are allowed!'


if __name__ == '__main__':
    app.run()
