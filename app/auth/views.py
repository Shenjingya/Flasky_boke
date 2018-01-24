# !/usr/bin/python
# -*-coding:utf-8 -*-
import send_email as send_email
from flask import render_template, redirect, request, url_for,flash
from flask_login import logout_user

from .import auth
from flask.ext.login import login_user,login_required,current_user
from ..models import User, db
from .forms import LoginForm, RegistrationForm,ChangePasswordForm,\
    PasswordResetForm,PasswordResetRequestForm,ChangeEmailForm

#登录
@auth.route('/login',method=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('/login.html ',form=form)
#登出
@auth.route('/logout')
@login_required
def logout():
    logout_user()#删除并重设用户会话
    flash('you have been logged out.')
    return redirect(url_for('main.index'))
#注册用户账户
@auth.route('/register',method=['GET','POST'])
def register():
    form=RegistrationForm()
    if form.validate_on_submit():
        user=User(email=form.email.data,
                  username=form.username.data,
                  password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token=user.generate_confirmation_token()
        send_email(user.email,'Confirm Your Account','auth/email/comfirm',user=user,token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('main_index'))
        #return redirect(url_for('auth.login'))
    return  render_template('auth/register.html',form=form)
#确认用户账户
@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account.Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))
#处理程序中过滤未确认的账户
@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint \
                and request.blueprint != 'auth' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous() or current_user.confirmed:
        return  redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')
#重新发送账户确认邮件
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token=current_user.generate_confirmation_token()
    send_email(current_user.email,'Confirm Your Account','auth/email/confirm',user=current_user,token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))

#修改密码
@auth.route('/change-password',method=['GET','POST'])
@login_required
def change_password():
    form=ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password=form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template('auth/change_password.html',form=form)

#重设密码
@auth.route('/reset',method=['GET','POST'])
@login_required
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form=PasswordResetRequestForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user:
           token=user.generate_reset_token()
           send_email(user.email,
                      'Reset Your Password','auth/email/reset_password.txt',
                      user=user,token=token,next=request.args.get('next'))
           flash('An email with instructions to reset your password has been sent to you.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html',form=form)

# 重设密码
@auth.route('/reset/<token>')
@login_required
def password_reset_request(token):
    if not current_user.is_anonymous:
        return  redirect(url_for('main.index'))
    form=PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token,form.password.data):
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html',form=form)

#修改电子邮箱地址
@auth.route('/change_email',method=['GET','POST'])
@login_required
def change_email_request():
    form=ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email=form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email,
                       'Confirm Your Email Address', 'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions to reset your password has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template("auth/change_email.html",form=form)



@auth.route('/change_email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        flash('Your email address has been updated.')
    else:
        flash('Invalid request')
    return redirect(url_for('main.index'))
#更新已登录用户的访问时间
@auth.before_app_request
def before_request():
    if current_user.is_authenticated():
        current_user.ping()
        if not current_user.confirmed and request.endpoint[:5]!='auth.':
            return redirect(url_for('auth.unconfirmed'))