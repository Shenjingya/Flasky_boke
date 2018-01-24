# !/usr/bin/python
# -*-coding:utf-8 -*-



#用户资料编辑器


from flask_wtf import Form,FlaskForm
from wtforms import StringField,IntegerField,TextAreaField,SubmitField,BooleanField,SelectField
from wtforms.validators import Length, Required, DataRequired, email, Regexp, ValidationError

#普通用户
from app.models import Role, User


class EditProfileForm(Form):
    name=StringField('Real name',validators=[Length(0,64)])
    location=StringField('Location',validators=[Length(0,64)])
    about_me=TextAreaField('About me')
    submit=SubmitField('Submit')
#管理员
class EditProfileAdminForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(),Length(0, 64),email()])
    username=StringField('Username',validators=[
        DataRequired(),Length(0,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters,''numbers,dots or underscores')])
    confirm=BooleanField('Confirmed')
    role=SelectField('Role',coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    #构造方法
    def __init__(self,user,*args,**kwargs):
        super(EditProfileAdminForm,self).__init__(*args,**kwargs)
        self.role.choices=[(role.id,role.name)for role in Role.query.order_by(Role.name).all]
        self.user=user
    def validate_email(self,field):
        if field.date!=self.user.email and User.query.filter_by(email=field.date).first():
            raise ValidationError('Email already registered.')
    def validate_username(self,field):
        if field.date!=self.user.username and User.query.filter_by(username=field.date).first():
            raise ValidationError('Username alreay in use.')

#博客文章表单
class PostForm(FlaskForm):
    body=TextAreaField('What is on your mind?',validators=[DataRequired()])
    submit=SubmitField('Submit')
