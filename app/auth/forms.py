# !/usr/bin/python
# -*-coding:utf-8 -*-
#添加登录表单

from  flask.ext.wtf import Form,FlaskForm
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo, email,DataRequired
from wtforms import ValidationError
from  ..models import User
#Regexp：验证函数
#登录表单
class LoginForm(Form):
    email=StringField('Email',validators=[Required(),Length(1,64),Email()])
    password=PasswordField('password',validators={Required()})
    remember_me=BooleanField('Keep me logged in')
    submit=SubmitField('Log in')
#注册表单
class RegistrationForm(Form):
    email=StringField('Email',validators=[Required(),Length(1,64),Email()])
    username=StringField('Username',validators=[
        Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters,''numbers,dots or underscores')])
    password=PasswordField('Password',validators=[Required(),EqualTo('password2',message='Passwords must match.')])
    password2=PasswordField('Confirm password',validators=[Required()])
    submit=SubmitField('Register')
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')
#修改密码表单
class ChangePasswordForm(FlaskForm):
    old_password=PasswordField('Old password',validators={DataRequired()})
    password=PasswordField('New password',validators={DataRequired(),EqualTo('password2',message='Passwords must match.')})
    password2=PasswordField('Confirm new password',validators={DataRequired()})
    submit=SubmitField('Update Password')
#重设密码
class PasswordResetRequestForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    submit=SubmitField('Reset Password')
class PasswordResetForm(FlaskForm):
    password=PasswordField('New password',validators=[DataRequired(),EqualTo('password2','Password must match.')])
    password2=PasswordField('Confirm password',validators=[DataRequired()])
    submit=SubmitField('Reset Password')

#修改电子邮箱地址
class ChangeEmailForm(FlaskForm):
    email=StringField('New Email',validators=[DataRequired(),Length(1,64),Email()])
    password = PasswordField('Password', validators={DataRequired()})
    sumbit=SubmitField('Update Email Address.')
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

