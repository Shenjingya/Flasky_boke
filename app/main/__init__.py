# !/usr/bin/python
# -*-coding:utf-8 -*-

#创建蓝本
from flask import Blueprint
main=Blueprint('main',__name__)

from .import views,errors
from ..models import Permission


#把Permission加入模板上下文中
@main.app_context_processor
def inject_permission():
    return dict(Permission=Permission)