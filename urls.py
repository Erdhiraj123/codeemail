"""
Create URLs for Account application.
"""

from django.urls import path
from . import views


urlpatterns = [
    path('', views.home_view, name="home"),
    path('register/', views.register_external_user_view, name="register_external_user"),
    path('login/', views.login_view, name="login"),
    path('logout/', views.logout_view, name="logout"),
    path("update_profile/", views.update_profile_view, name="update_profile"),

    path('forgetpassword/', views.forget_password_view, name="forget_password"),
    path('setpassword/<int:pk>', views.set_password_view, name="set_password"),
    path('reset_password/<uidb64>/<token>/', views.reset_password_view, name='reset_password'),
    path("change_password/", views.change_password_view, name="change_password"),

    path('manageregistration/', views.manage_registration_view, name="manage_registration"),
    path('approveuser/', views.approve_user_view, name="approve_user"),
    path("manage_agency_user/", views.manage_agency_user_view, name="manage_agency_user"),

    path("managedepartment/" , views.manage_department_view, name="manage_department"),
    path("adddepartment/", views.adddepartment, name="adddepartment"),
    path("updatedepartment/", views.updatedepartment, name="updatedepartment"),
    path("deletedepartment/<int:id>/", views.deletedepartment, name="deletedepartment"),
    path("getDepartmentData/<int:id>/", views.getDepartmentData_view , name="getDepartmentData"),
    path("filterdepartment/", views.filter_department_view , name="filterdepartment"), 

    path("managerank/", views.manage_rank_view, name="manage_rank"),
    path("dep_rank/", views.dep_rank_view, name="dep_rank"),
    path("editRank/<int:id>/", views.editRank_view , name="edit_rank"),
    path("updaterank/", views.updaterank_view, name="update_rank"),
    path("deleterank/<int:id>/", views.deleterank_view , name="delete_rank"),
    path("filterrank/", views.filterrank_view , name="filter_rank"),
    path("checkduplicatedepartment/", views.check_duplicateDepartment_view , name="check_duplicatedepartment"),
    path("checkduplicateUpdateview",views.check_duplicateUpdate_view,name="check_duplicateUpdate_view"),
    path('rankpost/<int:department_id>/',views.getrank,name='name'),
    path('signup/', views.signup, name='signup'),


    path("view_details/<int:id>/", views.view_details, name="viewdetails"),



]
