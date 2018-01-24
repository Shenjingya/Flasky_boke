# !/usr/bin/python
# -*-coding:utf-8 -*-


from os import abort

from flask import render_template, flash, redirect, url_for, request, current_app
from flask_login import login_required, current_user

from app import db
from forms import EditProfileForm,EditProfileAdminForm,PostForm
from app.main import main
from app.models import User, Permission, Post

#用户资料页面的路由
@main.route('/user/<username>')
def user(username):
    user=User.query.filter_by(username=username).first()
    if user is None:
        return abort(404)
    return render_template('user.html',user=user)

#普通用户资料编辑路由
@main.route('/edit-profile',method=['GET','POST'])
@login_required
def edit_profile():
    form=EditProfileForm()
    if form.validate_on_submit():
        current_user.name=form.name.data
        current_user.location=form.location.data
        current_user.about_me=form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been update.')
        return redirect(url_for('.user',username=current_user.username))
    form.name.data=current_user.name
    form.location.data=current_user.location
    form.about_me.data=current_user.about_me
    return render_template('edit_profile.html',form=form)

#管理员资料编辑
@main.route('/edit-profile/<int：id>',method=['GET','POST'])
@login_required
def edit_profile_admin(id):
    user=User.query.get_or_404(id)
    form=EditProfileAdminForm()
    if form.validate_on_submit():
        current_user.email = form.email.data
        current_user.username = form.username.data
        current_user.confirm = form.confirm.data
        current_user.role = form.role.data
        current_user.name=form.name.data
        current_user.location=form.location.data
        current_user.about_me=form.about_me.data
        db.session.add(current_user)
        flash('The profile has been update.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.email = current_user.email
    form.name.username = current_user.username
    form.name.confirm = current_user.confirm
    form.name.role = current_user.role
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form,user=user)

#处理博客文章的首页路由(视图函数)
@main.route('/',method=['GET','POST'])
def index():
    form=PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and form.validate_on_submit():
        post=Post(body=form.body.data,author=current_user._get_current_object())#文章对象
        db.session.add(post)
        return redirect(url_for('.index'))


    # 分页显示博客文章列表---页面中渲染数据
    page=request.args.get('page',1,type=int)# 渲染的页数 请求的查询字符串
    pagination=Post.query.order_by(Post.timestamp.desc()).paginate(
        page,per_page=current_app.config['FLASK_POSTS_PER_PAGE'],error_out=False)
    #FLASK_POSTS_PER_PAGE是程序的环境变量
    posts = pagination.items
    return render_template('index.html',form=form,posts=posts,pagination=pagination)

#获取博客文章的资料页路由
@main.route('user/<username>')
def user(username):
    user=User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts=user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html',user=user,posts=posts)